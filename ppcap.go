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
	PPCAP_VERSION                    = 3
	PPCAP_DEFAULT_MAX_BLOCK_MESSAGES = 256
	PPCAP_DEFAULT_MAX_BLOCK_SIZE     = 4096
	PPCAP_DEFAULT_FLUSH_INTERVAL_SEC = 60
	PPCAP_MAX_PACKET_SIZE            = 65535
	sizeofIndexFileHeader            = 256
	sizeofIndexEntry                 = 32
	fileSizeOffsetInHeader           = 16
	bufferSize                       = 1024 * 1024 // ideal write size

	// index file flags go below

	// added in version 2.
	HDRLAY_HAVE_STREAM_INDEX = 1 // 2 byte stream index follows the packet size.

	// added in version 3.
	HDRLAY_LIBPCAP = 2 // data file is original libpcap format (not pcap-NG). mutually exclusive with all other flags.
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
	Flags               uint32
	Size                int
	ProtocolHeadersSize int
	DataHeaderSize      int
	StreamIndexOffset   int
}

func BuildPacketHeaderLayout(hdrlay *PacketHeaderLayout, flags uint32) {
	size := 2
	streamIndexOffset := 0
	protocolHeadersSize := 0
	dataHeaderSize := 0
	if flags&HDRLAY_LIBPCAP > 0 {
		// NOTE: currently hardcoded for LINKTYPE_IPV4 + UDP
		size = 16
		protocolHeadersSize = 28
		dataHeaderSize = 24
	} else if flags&HDRLAY_HAVE_STREAM_INDEX > 0 {
		streamIndexOffset = size
		size += 2
	}
	*hdrlay = PacketHeaderLayout{
		Flags:               flags,
		Size:                size,
		ProtocolHeadersSize: protocolHeadersSize,
		DataHeaderSize:      dataHeaderSize,
		StreamIndexOffset:   streamIndexOffset,
	}
}

type IndexFileHeader struct {
	Magic                uint32
	Version              uint32
	CreationTimeUnix64   int64
	TimesOpenedForAppend uint32

	// added in version 2 to allow storing auxiliary per-packet data, e.g.
	// stream index if multiple streams are written in a single file.
	Flags            uint32 // 20:24
	reserved1        byte   // [24]
	PacketHeaderSize byte   // [25]

	// added in version 3 for libpcap support
	ProtocolHeadersSize uint16 // 26:28
	DataHeaderSize      uint32 // 28:32

	// reserved space
	HumanReadableDescription string // 128:255
}

func (hdr *IndexFileHeader) Parse(buf []byte) bool {
	if len(buf) < sizeofIndexFileHeader {
		return false
	}

	// Version 1
	hdr.Magic = binary.LittleEndian.Uint32(buf[0:4])
	hdr.Version = binary.LittleEndian.Uint32(buf[4:8])
	hdr.CreationTimeUnix64 = int64(binary.LittleEndian.Uint64(buf[8:16]))
	hdr.TimesOpenedForAppend = binary.LittleEndian.Uint32(buf[16:20])

	// Version 2
	hdr.Flags = binary.LittleEndian.Uint32(buf[20:24])
	hdr.reserved1 = buf[24]
	hdr.PacketHeaderSize = buf[25]
	if hdr.Version < 2 || hdr.PacketHeaderSize == 0 {
		hdr.PacketHeaderSize = 2
	}

	// Version 3
	hdr.ProtocolHeadersSize = binary.LittleEndian.Uint16(buf[26:28])
	hdr.DataHeaderSize = binary.LittleEndian.Uint32(buf[28:32])

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

func ReadPacketSize(wholePacket []byte, hdrlay *PacketHeaderLayout) (size int) {
	if hdrlay.Flags&HDRLAY_LIBPCAP > 0 {
		size = int(binary.LittleEndian.Uint32(wholePacket[8:12]))
	} else {
		size = int(binary.LittleEndian.Uint16(wholePacket[0:2]))
	}
	return
}

func ReadStreamIndex(wholePacket []byte, hdrlay *PacketHeaderLayout) (size uint16) {
	if hdrlay.Flags&HDRLAY_HAVE_STREAM_INDEX > 0 {
		size = binary.LittleEndian.Uint16(wholePacket[hdrlay.StreamIndexOffset:])
	}
	return
}

// no error checking because this block is known-good (i.e. already passed hashing)
func CountMessagesInKnownGoodBlock(block []byte, hdrlay *PacketHeaderLayout) int {
	count := 0
	for {
		count += 1
		psize := ReadPacketSize(block, hdrlay)
		block = block[hdrlay.Size+psize:]
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

func WriteDataFileHeader(dataFd *os.File, header *IndexFileHeader) error {
	if header.Flags&HDRLAY_LIBPCAP > 0 {
		buf := make([]byte, 24)
		/*
			guint32 magic_number;   // magic number
			guint16 version_major;  // major version number
			guint16 version_minor;  // minor version number
			gint32  thiszone;       // GMT to local correction
			guint32 sigfigs;        // accuracy of timestamps
			guint32 snaplen;        // max length of captured packets, in octets
			guint32 network;        // data link type
		*/
		binary.LittleEndian.PutUint32(buf[0:4], 0xa1b23c4d) // libpcap magic, nanosecond timestamps
		binary.LittleEndian.PutUint16(buf[4:6], 2)
		binary.LittleEndian.PutUint16(buf[6:8], 4)
		binary.LittleEndian.PutUint32(buf[20:24], 228) // LINKTYPE_IPV4
		if _, err := dataFd.WriteAt(buf, 0); err != nil {
			return err
		}
	}
	return nil
}

func WriteIndexFileHeader(indexFd *os.File, header *IndexFileHeader) error {
	buf := make([]byte, 256)

	// Version 1
	binary.LittleEndian.PutUint32(buf[0:4], header.Magic)
	binary.LittleEndian.PutUint32(buf[4:8], header.Version)
	binary.LittleEndian.PutUint64(buf[8:16], uint64(header.CreationTimeUnix64))
	binary.LittleEndian.PutUint32(buf[16:20], header.TimesOpenedForAppend)

	// Version 2
	binary.LittleEndian.PutUint32(buf[20:24], header.Flags)
	buf[25] = header.PacketHeaderSize

	// Version 3
	binary.LittleEndian.PutUint16(buf[26:28], header.ProtocolHeadersSize)
	binary.LittleEndian.PutUint32(buf[28:32], header.DataHeaderSize)

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

	if indexFileSize < sizeofIndexFileHeader {
		// no header
	} else {
		if err := ReadIndexFileHeader(indexFd, outHeader); err != nil {
			return err
		}
		if int(outHeader.PacketHeaderSize) != hdrlay.Size ||
			int(outHeader.DataHeaderSize) != hdrlay.DataHeaderSize ||
			int(outHeader.ProtocolHeadersSize) != hdrlay.ProtocolHeadersSize {
			return errors.New("capture file does not match header layout")
		}
		*outbValidExistingFile = true

		blockArrayByteLength := indexFileSize - sizeofIndexFileHeader
		numBlocks = blockArrayByteLength / sizeofIndexEntry
	}

	lastGoodIndexPosition := int64(sizeofIndexFileHeader)
	lastGoodDataPosition := int64(outHeader.DataHeaderSize)

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
		if blockEnd <= dataFileSize {
			blockBuf := dataBuf[:blockHdr.ByteCount]
			if _, err := dataFd.ReadAt(blockBuf, blockHdr.Position); err != nil {
				return err
			}
			hasher.Reset()
			hasher.Write(blockBuf)
			if hasher.Sum64() == blockHdr.Hash {
				messageCount := CountMessagesInKnownGoodBlock(blockBuf, hdrlay)
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
