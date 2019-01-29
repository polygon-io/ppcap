package ppcap

// PPCAP is the Polygon.io Packet CAPture format

// A PPCAP consists of two files, a "data" file and an "index" file.

// The data format is simply an EOF-terminated list of
// [len][packet][len][packet] ...
// where [len] is 2-byte little endian, and [packet] is the raw data.
// The data format can be parsed without the index file, assuming
// that it has not been corrupted. Due to the "forward iterator"
// nature of the data file, any corruption may make following
// records unreadable.
//
// The index format is auxiliary data which supports searching
// and error detection. It consists of a simple file header
// followed by a number of fixed-length entries which point
// to blocks inside the data file. Each block has a checksum,
// local machine capture timestamp and some sequencing info.
//
// If the data file has been corrupted, the index file can
// most likely still be used to recover some of the data.
// If both files have been corrupted, it is likely still
// possible to recover some data because the index records
// have fixed length and so can be looked up independently.
//
// Both the index and data formats are essentially "vectors"
// i.e. they are a block of memory that only grow on the right.
// This means that they are suitable for use with concurrent
// readers and memory mapped techniques. The fixed-length
// records of the index format also make it suitable
// for sub-linear (e.g. binary or otherwise) searching.
//
// The overhead of the index is less than 1% with the default
// parameters, (sizeofIndexEntry / PPCAP_DEFAULT_MAX_BLOCK_SIZE)
// but this can be tweaked when the writer is constructed.

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
	PPCAP_VERSION                    = 1
	PPCAP_DEFAULT_MAX_BLOCK_MESSAGES = 256
	PPCAP_DEFAULT_MAX_BLOCK_SIZE     = 4096
	PPCAP_DEFAULT_FLUSH_INTERVAL_SEC = 60
	PPCAP_MAX_PACKET_SIZE            = 65535
	sizeofIndexFileHeader            = 256
	sizeofIndexEntry                 = 32
	sizeofPacketHeader               = 2 // just the length (16 bits)
	fileSizeOffsetInHeader           = 16
	bufferSize                       = 1024 * 1024 // ideal write size
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

type IndexFileHeader struct {
	Magic                uint32
	Version              uint32
	CreationTimeUnix64   int64
	TimesOpenedForAppend uint32
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
			position: 6
			seq_num: 6
			length: 4
			time:8
	*/

	hash      uint64
	position  int64 // store as 6 byte
	seqNum    int64 // store as 6 byte
	byteCount int
	time      int64 // (unix time in nanoseconds) of the first message in this block

	// not written on disk
	messageCount int
}

func (b *BlockInfo) Parse(buf []byte) bool {
	if len(buf) < 32 {
		return false
	}

	b.hash = binary.LittleEndian.Uint64(buf[0:8])
	b.position = int64(littleEndian_Uint48(buf[8:14]))
	b.seqNum = int64(littleEndian_Uint48(buf[14:20]))
	b.byteCount = int(binary.LittleEndian.Uint32(buf[20:24]))
	b.time = int64(binary.LittleEndian.Uint32(buf[24:32]))

	return true
}

// no error checking because this block is known-good (i.e. already passed hashing)
func CountMessagesInKnownGoodBlock(block []byte) int {
	count := 0
	for {
		count += 1
		psize := binary.LittleEndian.Uint16(block[0:2])
		block = block[2+psize:]
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

	copy(buf[128:255], []byte(header.HumanReadableDescription))

	if _, err := indexFd.WriteAt(buf, 0); err != nil {
		return err
	}

	return nil
}

// ReopenAndTruncateExistingCapture opens a capture and truncates any invalid
//   blocks between the end and the last valid block. The purpose of this
//   is to re-synchronize the .*d and .*i files following an unclean shutdown.
// This should always be performed before appending to an existing capture,
//   to ensure that the data file remains parsable without the index.
// Note that this function is *NOT* meant to be an extensive integrity check,
//   and data _before_ the last valid block is not scanned for errors.
func ReopenAndTruncateExistingCapture(
	indexPath string,
	dataPath string,
	outbValidExistingFile *bool,
	outHeader *IndexFileHeader,
	outMessageSequence *int64) error {

	// first, set all "out" variables
	*outbValidExistingFile = false
	*outHeader = IndexFileHeader{}
	*outMessageSequence = 0

	// open both files (and make sure they get closed)
	indexFd, indexErr := os.OpenFile(indexPath, os.O_RDWR, 0644)
	defer indexFd.Close()
	dataFd, dataErr := os.OpenFile(dataPath, os.O_RDWR, 0644)
	defer dataFd.Close()

	if indexErr == nil && dataErr == nil {
		// ok, both files opened successfully
	} else if os.IsNotExist(indexErr) && os.IsNotExist(dataErr) {
		// ok, neither file exists yet
		return nil
	} else {
		// something went wrong
		if os.IsNotExist(indexErr) || indexErr == nil {
			return dataErr
		}
		return indexErr
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
	dataBuf := make([]byte, PPCAP_DEFAULT_MAX_BLOCK_SIZE)
	for blockIdx := numBlocks - 1; blockIdx >= 0; blockIdx-- {
		indexEntryOffset := sizeofIndexFileHeader + blockIdx*sizeofIndexEntry
		if _, err := indexFd.ReadAt(hdrBuf, indexEntryOffset); err != nil {
			return err
		}
		blockHdr.Parse(hdrBuf) // always succeeds
		if blockHdr.byteCount > cap(dataBuf) {
			dataBuf = make([]byte, blockHdr.byteCount)
		}
		blockEnd := blockHdr.position + int64(blockHdr.byteCount)
		if blockEnd < dataFileSize {
			blockBuf := dataBuf[:blockHdr.byteCount]
			if _, err := dataFd.ReadAt(blockBuf, blockHdr.position); err != nil {
				return err
			}
			hasher.Reset()
			hasher.Write(blockBuf)
			if hasher.Sum64() == blockHdr.hash {
				messageCount := CountMessagesInKnownGoodBlock(blockBuf)
				*outMessageSequence = blockHdr.seqNum + int64(messageCount)
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
