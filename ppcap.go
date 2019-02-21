package ppcap

import (
	"encoding/binary"
	"errors"
	"os"
	"strings"

	xxhash "github.com/OneOfOne/xxhash"
)

const (
	PPCAP_DEBUG = false
)

const (
	PPCAP_DATA_EXTENSION             = ".ppcapd"
	PPCAP_INDEX_EXTENSION            = ".ppcapi"
	PPCAP_MAGIC                      = 0x594c4f50 // 'POLY' (looks like text)
	PPCAP_VERSION                    = 2
	PPCAP_DEFAULT_MAX_BLOCK_MESSAGES = 256
	PPCAP_DEFAULT_MAX_BLOCK_SIZE     = 4096
	PPCAP_DEFAULT_FLUSH_INTERVAL_SEC = 60
	PPCAP_MAX_PACKET_SIZE            = 65535
	sizeofIndexFileHeader            = 256
	sizeofIndexEntry                 = 32
	fileSizeOffsetInHeader           = 16
	bufferSize                       = 1024 * 1024 // ideal write size

	// index file flags go below
	HDRLAY_HAVE_STREAM_INDEX = 1
)

///////// INTERNAL UTILITY FUNCTIONS

func getFileSize(f *os.File) (int64, error) {
	fi, err := f.Stat()
	if err != nil {
		return 0, err
	}
	return fi.Size(), nil
}

func littleEndian_PutUint48(b []byte, v uint64) {
	_ = b[5] // early bounds check to guarantee safety of writes below
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
	b[4] = byte(v >> 32)
	b[5] = byte(v >> 40)
}

func littleEndian_Uint48(b []byte) uint64 {
	_ = b[5] // bounds check hint to compiler; see golang.org/issue/14808
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40
}

///////// BASIC DATSTRUCTURES

type PacketHeaderLayout struct {
	Flags             uint32 // from IndexFileHeader
	Size              int    // from IndexFileHeader
	StreamIndexOffset int    // computed from flags
}

func BuildPacketHeaderLayout(hdrlay *PacketHeaderLayout, Flags uint32) {
	hdrlay.Flags = Flags
	size := 2 // length
	if hdrlay.Flags&HDRLAY_HAVE_STREAM_INDEX > 0 {
		hdrlay.StreamIndexOffset = size
		size += 2
	}
	hdrlay.Size = size
}

type IndexFileHeader struct {
	Magic                uint32
	Version              uint32
	CreationTimeUnix64   int64
	TimesOpenedForAppend uint32

	// added in version 2 to allow storing auxiliary per-packet data, e.g.
	// stream index if multiple streams are written in a single file.
	Flags            uint32
	PacketHeaderSize byte

	// reserved space
	HumanReadableDescription string // 128:255
}

func (hdr *IndexFileHeader) Parse(buf []byte) bool {
	if len(buf) < sizeofIndexFileHeader {
		return false
	}
	hdr.Magic = binary.LittleEndian.Uint32(buf[0:4])
	hdr.Version = binary.LittleEndian.Uint32(buf[4:8])
	hdr.CreationTimeUnix64 = int64(binary.LittleEndian.Uint64(buf[8:16]))
	hdr.TimesOpenedForAppend = binary.LittleEndian.Uint32(buf[16:20])
	hdr.Flags = binary.LittleEndian.Uint32(buf[20:24]) // added in version 2
	hdr.PacketHeaderSize = buf[25]                     // added in version 2
	if hdr.Version < 2 || hdr.PacketHeaderSize == 0 {
		hdr.PacketHeaderSize = 2
	}

	hdr.HumanReadableDescription = strings.TrimRight(string(buf[128:255]), "\x00")

	if hdr.Magic != PPCAP_MAGIC {
		return false
	}

	return true
}

type BlockInfo struct {

	/*
		disk representation:
			hash:8
			position:6
			seq_num:6
			length:4
			time:8

		total = 32 bytes
	*/

	Hash      uint64
	Position  int64 // store as 6 byte
	SeqNum    int64 // store as 6 byte
	ByteCount int
	Time      int64 // (unix time in nanoseconds) of the first message in this block
}

func (b *BlockInfo) Parse(buf []byte) bool {
	if len(buf) < 32 {
		return false
	}

	b.Hash = binary.LittleEndian.Uint64(buf[0:8])
	b.Position = int64(littleEndian_Uint48(buf[8:14]))
	b.SeqNum = int64(littleEndian_Uint48(buf[14:20]))
	b.ByteCount = int(binary.LittleEndian.Uint32(buf[20:24]))
	b.Time = int64(binary.LittleEndian.Uint32(buf[24:32]))

	return true
}

// no error checking because this block is known-good (i.e. already passed hashing)
func CountMessagesInKnownGoodBlock(block []byte, packetHeaderSize int) int {
	count := 0
	for {
		count += 1
		psize := int(binary.LittleEndian.Uint16(block[0:2]))
		block = block[packetHeaderSize+psize:]
		if len(block) <= 0 {
			break
		}
	}
	return count
}

func ReadIndexFileHeader(indexFd *os.File, header *IndexFileHeader) error {
	buf := make([]byte, 256)
	_, err := indexFd.ReadAt(buf, 0)
	if err != nil {
		return err
	}

	if !header.Parse(buf) {
		return errors.New("failed parsing ppcap index file header")
	}

	return nil
}

func WriteIndexFileHeader(indexFd *os.File, header *IndexFileHeader) error {
	buf := make([]byte, 256)

	binary.LittleEndian.PutUint32(buf[0:4], header.Magic)
	binary.LittleEndian.PutUint32(buf[4:8], header.Version)
	binary.LittleEndian.PutUint64(buf[8:16], uint64(header.CreationTimeUnix64))
	binary.LittleEndian.PutUint32(buf[16:20], header.TimesOpenedForAppend)
	binary.LittleEndian.PutUint32(buf[20:24], header.Flags)
	buf[25] = header.PacketHeaderSize

	copy(buf[128:255], []byte(header.HumanReadableDescription))

	if _, err := indexFd.WriteAt(buf, 0); err != nil {
		return err
	}

	return nil
}

type CapturePath struct {
	BasePath         string // this is used if nonempty, otherwise the individual index/data paths are used
	DataPath         string
	IndexPath        string
	ManualExtensions bool // if set, .ppcapd and .ppcapi are not automatically added
}

func (where *CapturePath) BuildPaths() (string, string) {
	var indexPath string
	var dataPath string
	if len(where.BasePath) > 0 {
		indexPath = where.BasePath
		dataPath = where.BasePath
	} else {
		indexPath = where.IndexPath
		dataPath = where.DataPath
	}
	if !where.ManualExtensions {
		indexPath += PPCAP_INDEX_EXTENSION
		dataPath += PPCAP_DATA_EXTENSION
	}
	if indexPath == dataPath {
		panic("that's not going to work")
	}
	return indexPath, dataPath
}

func OpenCapture(where *CapturePath, flag int, perm os.FileMode) (indexFd *os.File, dataFd *os.File, err error) {
	indexPath, dataPath := where.BuildPaths()
	indexFd, indexErr := os.OpenFile(indexPath, flag, perm)
	dataFd, dataErr := os.OpenFile(dataPath, flag, perm)

	if indexErr == nil && dataErr == nil {
		// ok, both files opened successfully
	} else if os.IsNotExist(indexErr) && os.IsNotExist(dataErr) {
		// ok, neither file exists yet
		return nil, nil, nil
	} else {
		// something went wrong
		if os.IsNotExist(indexErr) || indexErr == nil {
			err = dataErr
		}
		err = indexErr
	}

	if err != nil {
		indexFd.Close()
		dataFd.Close()
		dataFd = nil
		indexFd = nil
	}

	return
}

// ReopenAndTruncateExistingCapture opens a capture and truncates any invalid
//   blocks between the end and the last valid block. The purpose of this
//   is to re-synchronize the .*d and .*i files following an unclean shutdown.
// This should always be performed before appending to an existing capture,
//   to ensure that the data file remains parsable without the index.
// Note that this function is *NOT* meant to be an extensive integrity check,
//   and data _before_ the last valid block is not scanned for errors.
func ReopenAndTruncateExistingCapture(
	where *CapturePath,
	hdrlay *PacketHeaderLayout,
	outbValidExistingFile *bool,
	outHeader *IndexFileHeader,
	outMessageSequence *int64) error {

	// first, set all "out" variables
	*outbValidExistingFile = false
	*outHeader = IndexFileHeader{}
	*outMessageSequence = 0

	indexFd, dataFd, err := OpenCapture(where, os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	if indexFd == nil && dataFd == nil {
		// ok, neither file exists yet
		return nil
	}
	if indexFd == nil || dataFd == nil {
		panic("shouldn't happen")
	}

	// below, both files are open

	indexFileSize, err := getFileSize(indexFd)
	if err != nil {
		return err
	}

	dataFileSize, err := getFileSize(dataFd)
	if err != nil {
		return err
	}

	numBlocks := int64(0)

	lastGoodIndexPosition := int64(sizeofIndexFileHeader)
	lastGoodDataPosition := int64(0)

	if indexFileSize < sizeofIndexFileHeader {
		// no header
	} else {
		if err := ReadIndexFileHeader(indexFd, outHeader); err != nil {
			return err
		}
		*outbValidExistingFile = true

		blockArrayByteLength := indexFileSize - sizeofIndexFileHeader
		numBlocks = blockArrayByteLength / sizeofIndexEntry
	}

	// iterate backwards from the last readable block header,
	// looking for a valid block

	var hasher xxhash.XXHash64
	var blockHdr BlockInfo
	hdrBuf := make([]byte, sizeofIndexEntry)
	dataBuf := make([]byte, 2*PPCAP_DEFAULT_MAX_BLOCK_SIZE)
	for blockIdx := numBlocks - 1; blockIdx >= 0; blockIdx-- {
		indexEntryOffset := sizeofIndexFileHeader + blockIdx*sizeofIndexEntry
		if _, err := indexFd.ReadAt(hdrBuf, indexEntryOffset); err != nil {
			return err
		}
		blockHdr.Parse(hdrBuf) // always succeeds
		if blockHdr.ByteCount > cap(dataBuf) {
			dataBuf = make([]byte, 2*blockHdr.ByteCount)
		}
		blockEnd := blockHdr.Position + int64(blockHdr.ByteCount)
		if blockEnd < dataFileSize {
			blockBuf := dataBuf[:blockHdr.ByteCount]
			if _, err := dataFd.ReadAt(blockBuf, blockHdr.Position); err != nil {
				return err
			}
			hasher.Reset()
			hasher.Write(blockBuf)
			if hasher.Sum64() == blockHdr.Hash {
				messageCount := CountMessagesInKnownGoodBlock(blockBuf, hdrlay.Size)
				*outMessageSequence = blockHdr.SeqNum + int64(messageCount)
				// matched successfully
				lastGoodIndexPosition = indexEntryOffset + sizeofIndexEntry
				lastGoodDataPosition = blockEnd
				break
			}
		}
	}

	if indexFileSize != lastGoodIndexPosition {
		if err := indexFd.Truncate(lastGoodIndexPosition); err != nil {
			return err
		}
	}

	if dataFileSize != lastGoodDataPosition {
		if err := dataFd.Truncate(lastGoodDataPosition); err != nil {
			return err
		}
	}

	return nil
}
