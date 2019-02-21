package ppcap

import (
	"encoding/binary"
	"io"
	"os"
	"reflect"

	"github.com/OneOfOne/xxhash"
)

// DataReadStream is used for streaming packets from a ppcapd (data file).
// Can be used with or without the corresponding index file.
// If used with an index file, call SetReadRange to iterate inside a
// specific range of blocks (or a single block), then NextPacket until EOF.
type DataReadStream struct {
	hdrlay          PacketHeaderLayout
	iseof           bool // is the DataReadStream at EOF
	isunderlyingeof bool // is the underlying dataFile at EOF

	reader       io.ReaderAt
	buf          []byte
	bufferOffset int64
	bufferUsed   int
	bufferAvail  int
	endOffset    int64 // if we are, e.g. reading inside one particular block
}

type NextPacketOutput struct {
	PayloadSize     uint16 // filled if possible
	StreamIndex     uint16 // filled if possible
	WholePacketSize uint32 // filled if possible
	Header          []byte // filled only on success
	Payload         []byte // filled only on success
	WholePacket     []byte // filled only on success
}

// generic next packet on byte slice
func NextPacket(stream *[]byte, hdrlay *PacketHeaderLayout, output *NextPacketOutput) bool {
	read := *stream
	*output = NextPacketOutput{}
	if len(read) < hdrlay.Size {
		return false
	}
	output.PayloadSize = binary.LittleEndian.Uint16(read[0:2])
	wholePacketSize := hdrlay.Size + int(output.PayloadSize)
	output.WholePacketSize = uint32(wholePacketSize)
	if len(read) < wholePacketSize {
		return false
	}
	output.StreamIndex = 0
	if hdrlay.Flags&HDRLAY_HAVE_STREAM_INDEX > 0 {
		offset := hdrlay.StreamIndexOffset
		output.StreamIndex = binary.LittleEndian.Uint16(read[offset : offset+2])
	}
	// advance stream
	*stream = read[wholePacketSize:]
	output.WholePacket = read[:wholePacketSize]
	output.Header = read[:hdrlay.Size]
	output.Payload = read[hdrlay.Size:wholePacketSize]
	return true
}

func NewDataReadStream(reader io.ReaderAt, hdrlay *PacketHeaderLayout) *DataReadStream {
	rs := &DataReadStream{}
	rs.hdrlay = *hdrlay
	rs.reader = reader
	rs.buf = make([]byte, 2*PPCAP_DEFAULT_MAX_BLOCK_SIZE)
	rs.reset()
	return rs
}

func (rs *DataReadStream) refillBuffer(packetLen int) error {
	copy(rs.buf, rs.buf[rs.bufferUsed:])
	if packetLen*16 > cap(rs.buf) {
		// make space for 16x the largest packet, so that the
		// circular buffer scheme doesn't have too much copying overhead
		newbuf := make([]byte, packetLen*16)
		copy(newbuf, rs.buf)
		rs.buf = newbuf
	}
	dest := rs.buf[rs.bufferAvail:]
	readSize := len(dest)
	if rs.endOffset > 0 {
		remaining := rs.endOffset - rs.bufferOffset
		if remaining < int64(readSize) {
			readSize = int(remaining)
			dest = rs.buf[rs.bufferAvail : rs.bufferAvail+readSize]
		}
	}
	if readSize == 0 {
		rs.isunderlyingeof = true
		return io.EOF
	} else {
		count, err := rs.reader.ReadAt(dest, rs.bufferOffset)
		rs.bufferOffset += int64(count)
		rs.bufferAvail += count
		rs.bufferUsed = 0
		if err == io.EOF {
			rs.isunderlyingeof = true
			return nil
		} else {
			return err
		}
	}
}

func (rs *DataReadStream) reset() {
	rs.iseof = false
	rs.isunderlyingeof = false
	rs.bufferOffset = 0
	rs.bufferAvail = 0
	rs.bufferUsed = len(rs.buf)
	rs.endOffset = 0
}

// SetReadRange sets up the stream for reading a given range of blocks.
// if start = nil then reading will begin at offset 0.
// if end = nil then reading will end at EOF.
func (rs *DataReadStream) SetReadRange(start *BlockInfo, end *BlockInfo) {
	rs.reset()
	if start != nil {
		rs.bufferOffset = start.Position
	}
	if end != nil {
		rs.endOffset = end.Position + int64(end.ByteCount)
	}
}

// ReadNextPacket returns a byte slice containing the next packet in the current read range.
// Once the last packet has been returned, any subsequent calls will EOF.
// If there is a partial packet at the end of the read range, io.ErrUnexpectedEOF is raised.
func (rs *DataReadStream) ReadNextPacket(output *NextPacketOutput) error {
	for {
		// handle EOF
		if rs.iseof {
			if rs.bufferAvail == 0 {
				return io.EOF
			}
			return io.ErrUnexpectedEOF
		}

		rdbuf := rs.buf[rs.bufferUsed : rs.bufferUsed+rs.bufferAvail]
		success := NextPacket(&rdbuf, &rs.hdrlay, output)
		wholePacketSize := int(output.WholePacketSize)
		if success {
			rs.bufferAvail -= wholePacketSize
			rs.bufferUsed += wholePacketSize
			return nil
		} else {
			// read more unless the underlying file is already EOF
			if rs.isunderlyingeof {
				rs.iseof = true
			} else {
				err := rs.refillBuffer(wholePacketSize)
				if err != nil {
					return err
				}
			}
		}
	}
}

func GetNumberOfBlocks(indexFileSize int64, IsTruncated *bool) int {
	if indexFileSize < sizeofIndexFileHeader {
		return 0
	}
	indexFileSize -= sizeofIndexFileHeader
	*IsTruncated = ((indexFileSize % sizeofIndexEntry) != 0)
	return int(indexFileSize / int64(sizeofIndexEntry))
}

func ReadBlockHeaders(indexFd *os.File, headers []BlockInfo, firstBlock int) error {
	if len(headers) == 0 {
		return nil
	}

	bufSize := 4096
	buf := make([]byte, bufSize)

	offset := int64(firstBlock)*sizeofIndexEntry + sizeofIndexFileHeader
	for {
		blocksToRead := len(headers)
		if blocksToRead*sizeofIndexEntry > bufSize {
			blocksToRead = bufSize / sizeofIndexEntry
		}
		raw := buf[:blocksToRead*sizeofIndexEntry]
		_, err := indexFd.ReadAt(raw, offset)
		if err != nil {
			return err
		}
		for i, _ := range headers[:blocksToRead] {
			hdr := &headers[i]
			hdr.Parse(raw[i*sizeofIndexEntry:])
		}
		offset += int64(blocksToRead) * sizeofIndexEntry
		headers = headers[blocksToRead:]
		if len(headers) == 0 {
			break
		}
	}

	return nil
}

// TODO (?):
// Implement a reader class that can read a capture while it
// is being concurrently written by another thread/process.
// This requires thought, and it might not be possible to do generically enough
// given that users will likely want to maintain side datastructures for blocks
type ConcurrentIndexReader struct {
}

// The SimpleInMemoryIndex is suitable for offline use cases
// where the pcap file is not being concurrently written.
// Use ReadIndexIntoMemory to create.
type SimpleInMemoryIndex struct {
	Layout        PacketHeaderLayout
	IndexHeader   IndexFileHeader
	Blocks        []BlockInfo
	BlockCount    int
	IndexFileSize int64
	IsTruncated   bool
}

func ReadIndexIntoMemory(indexFd *os.File) (*SimpleInMemoryIndex, error) {
	memidx := &SimpleInMemoryIndex{}
	err := ReadIndexFileHeader(indexFd, &memidx.IndexHeader)
	if err != nil {
		return nil, err
	}

	BuildPacketHeaderLayout(&memidx.Layout, memidx.IndexHeader.Flags)

	memidx.IndexFileSize, err = getFileSize(indexFd)
	if err != nil {
		return nil, err
	}

	memidx.BlockCount = GetNumberOfBlocks(memidx.IndexFileSize, &memidx.IsTruncated)
	memidx.Blocks = make([]BlockInfo, memidx.BlockCount)
	err = ReadBlockHeaders(indexFd, memidx.Blocks, 0)
	if err != nil {
		return nil, err
	}

	return memidx, nil
}

type EvaluateCaptureResult struct {
	IndexHeader       IndexFileHeader
	AppearsFlawless   bool // all hashes passed, no truncation, sequence numbers OK
	IndexIsTruncated  bool
	DataIsTruncated   bool
	IsTruncated       bool
	SequencingOk      bool
	AllBlocksPassed   bool
	TotalBlockCount   int
	GoodBlockCount    int
	FailedBlockCount  int
	PacketCount       int64
	DataSize          int64
	IndexSize         int64
	TotalSize         int64
	TotalPayloadSize  int64 // overhead = 100% * (TotalPayloadSize/TotalSize-1)
	PacketStreamCount int
	PacketStreamHash  map[uint16]uint64 // hash for each stream index
}

func EvaluateCapture(where *CapturePath, result *EvaluateCaptureResult) error {
	*result = EvaluateCaptureResult{}

	// open as readonly exlcusive to ensure that a writer isn't currently active on this capture
	indexFd, dataFd, err := OpenCapture(where, os.O_RDONLY, 0644|os.ModeExclusive)
	if err != nil {
		return err
	}

	defer indexFd.Close()
	defer dataFd.Close()

	if indexFd == nil || dataFd == nil {
		return os.ErrNotExist
	}

	memidx, err := ReadIndexIntoMemory(indexFd)
	if err != nil {
		return err
	}

	indexFileSize := memidx.IndexFileSize
	blockCount := memidx.BlockCount
	blockHeaders := memidx.Blocks

	dataFileSize, err := getFileSize(dataFd)
	if err != nil {
		return err
	}

	dataStream := NewDataReadStream(dataFd, &memidx.Layout)

	if blockCount > 0 {
		blockHdr := &blockHeaders[blockCount-1]
		dataEnd := blockHdr.Position + int64(blockHdr.ByteCount)
		if dataEnd > dataFileSize {
			result.DataIsTruncated = true
		}
		if dataEnd < dataFileSize {
			result.IndexIsTruncated = true
		}
	}

	var packet NextPacketOutput
	var blockHash xxhash.XXHash64
	streamHashes := make(map[uint16]*xxhash.XXHash64)
	result.SequencingOk = true
	for blockIdx := 0; blockIdx < blockCount; blockIdx++ {
		blockHdr := &blockHeaders[blockIdx]
		dataStream.SetReadRange(blockHdr, blockHdr)
		blockHash.Reset()
		if result.PacketCount != blockHdr.SeqNum {
			result.SequencingOk = false
		}
		for {
			err := dataStream.ReadNextPacket(&packet)
			if err != nil {
				if err != io.EOF {
					// block read error
					// don't bail entirely here, just go to the next block
				}
				break
			}
			if streamHashes[packet.StreamIndex] == nil {
				streamHashes[packet.StreamIndex] = xxhash.New64()
			}
			streamHashes[packet.StreamIndex].Write(packet.Payload)
			blockHash.Write(packet.WholePacket)
			result.PacketCount += 1
			result.TotalPayloadSize += int64(len(packet.Payload))
		}
		if blockHash.Sum64() == blockHdr.Hash {
			result.GoodBlockCount += 1
		} else {
			result.FailedBlockCount += 1
		}
		result.TotalBlockCount += 1
	}

	result.PacketStreamHash = make(map[uint16]uint64)
	for k, v := range streamHashes {
		result.PacketStreamHash[k] = v.Sum64()
	}
	result.PacketStreamCount = len(result.PacketStreamHash)

	result.DataSize = dataFileSize
	result.IndexSize = indexFileSize
	result.TotalSize = indexFileSize + dataFileSize
	result.IndexHeader = memidx.IndexHeader

	result.AllBlocksPassed = (result.FailedBlockCount == 0)
	result.IsTruncated = result.DataIsTruncated || result.IndexIsTruncated
	result.AppearsFlawless = result.AllBlocksPassed && !result.IsTruncated && result.SequencingOk

	return nil
}

func CapturesMatch(a, b *EvaluateCaptureResult) bool {
	if !a.AppearsFlawless || !b.AppearsFlawless {
		// initial implementation: don't even try to match if there could be some kind of error
		return false
	}
	if a.DataSize != b.DataSize {
		return false
	}
	return reflect.DeepEqual(a.PacketStreamHash, b.PacketStreamHash)
}
