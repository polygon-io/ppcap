package ppcap

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"time"

	//"github.com/cespare/xxhash"
	xxhash "github.com/OneOfOne/xxhash"
)

type Writer struct {
	HumanReadableDescription string

	// private members
	isOpen               bool
	good                 bool
	header               IndexFileHeader
	hdrlay               PacketHeaderLayout
	dataFd               *os.File
	dataWriter           *BufferedWriter
	indexFd              *os.File
	indexWriter          *BufferedWriter
	currentBlockHash     xxhash.XXHash64
	currentBlockMsgCount int
	currentBlock         BlockInfo
	messageSequence      int64 // increments by one every time we append a message; also set when we re-open for append
	lastFlushTime        int64
	maxMessagesPerBlock  int
	maxBytesPerBlock     int
	maxFlushIntervalNs   int64
	protocolHeaders      []byte
}

func NewWriter(humanReadableDescription string, layout PacketHeaderLayout) *Writer {
	w := &Writer{}
	w.maxMessagesPerBlock = PPCAP_DEFAULT_MAX_BLOCK_MESSAGES
	w.maxBytesPerBlock = PPCAP_DEFAULT_MAX_BLOCK_SIZE
	w.maxFlushIntervalNs = 1000000000 * PPCAP_DEFAULT_FLUSH_INTERVAL_SEC
	w.HumanReadableDescription = humanReadableDescription
	w.hdrlay = layout
	w.lastFlushTime = time.Now().UnixNano()
	return w
}

func (w *Writer) SetLimits(maxMessagesPerBlock int, maxBytesPerBlock int, maxFlushIntervalInSec int) {
	if maxMessagesPerBlock < 1 {
		maxMessagesPerBlock = 1
	}
	if maxBytesPerBlock < 1 {
		maxBytesPerBlock = 1
	}
	w.maxMessagesPerBlock = maxMessagesPerBlock
	w.maxBytesPerBlock = maxBytesPerBlock
	w.maxFlushIntervalNs = 1000000000 * int64(maxFlushIntervalInSec)
}

func (w *Writer) Open(basePath string) error {
	if w.isOpen {
		panic("Writer object is not designed to be reused")
	}

	where := &CapturePath{BasePath: basePath}
	w.isOpen = true

	defer func() {
		if !w.good {
			// cleanup all resources
			w.Close()
		}
	}()

	var err error

	// handle appending to existing captures

	var validExistingFile bool
	var messageSequence int64
	if err = ReopenAndTruncateExistingCapture(where, &w.hdrlay,
		&validExistingFile, &w.header, &messageSequence); err != nil {
		return err
	}

	// setup header data

	if validExistingFile {
		w.header.TimesOpenedForAppend += 1
		w.messageSequence = messageSequence
	} else {
		w.header.CreationTimeUnix64 = time.Now().Unix()
		// w.messageSequence = 0 // is already zero via default init
	}

	// open files (create,writeonly), update header on disk

	w.indexFd, w.dataFd, err = OpenCapture(where, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	if w.indexFd == nil || w.dataFd == nil {
		panic("shouldn't happen")
	}

	w.header.Magic = PPCAP_MAGIC
	w.header.Version = PPCAP_VERSION
	w.header.HumanReadableDescription = w.HumanReadableDescription
	w.header.PacketHeaderSize = byte(w.hdrlay.Size)
	w.header.Flags = w.hdrlay.Flags
	w.header.ProtocolHeadersSize = uint16(w.hdrlay.ProtocolHeadersSize)
	w.header.DataHeaderSize = uint32(w.hdrlay.DataHeaderSize)

	if err = WriteDataFileHeader(w.dataFd, &w.header); err != nil {
		return err
	}

	if err = WriteIndexFileHeader(w.indexFd, &w.header); err != nil {
		return err
	}

	// create write buffers

	w.protocolHeaders = make([]byte, w.header.ProtocolHeadersSize)

	w.indexWriter, err = NewBufferedWriter(w.indexFd, bufferSize)
	if err != nil {
		return err
	}

	w.dataWriter, err = NewBufferedWriter(w.dataFd, bufferSize)
	if err != nil {
		return err
	}

	w.good = true

	return nil
}

func (w *Writer) Close() error {
	var cerr1, cerr2 error

	flushErr := w.finishCurrentBlock(true, 0)

	if w.indexFd != nil {
		cerr1 = w.indexFd.Close()
	}
	if w.dataFd != nil {
		cerr2 = w.dataFd.Close()
	}
	if flushErr != nil {
		return flushErr
	}
	if cerr1 != nil {
		return cerr1
	}
	if cerr2 != nil {
		return cerr2
	}
	return nil
}

func ipChecksum(b []byte) uint16 {
	sum := uint32(0)
	for i := 0; i < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	for (sum >> 16) > 0 {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return uint16(^sum)
}

func (w *Writer) AppendFakeIPV4UDP(payload []byte, packetReadTime int64,
	ipSourceAddr uint32, ipDestAddr uint32,
	udpSourcePort uint16, udpDestPort uint16) error {
	headers := w.protocolHeaders[0:28]

	/*
		uint8_t  ip_v_hl;       // version & header length
		uint8_t  ip_tos;        // type of service
		uint16_t ip_len;        // total length
		uint16_t ip_id;	        // identification
		uint16_t ip_off;        // fragment offset field
		uint8_t  ip_ttl;        // time to live
		uint8_t  ip_p;	        // protocol
		uint16_t ip_sum;        // checksum
		uint32_t ip_src,ip_dst; // source and dest address
	*/
	ipv4 := headers[0:20]

	/*
		uint16_t src_port;
		uint16_t dst_port;
		uint16_t len;
		uint16_t checksum;
	*/
	udp := headers[20:28]

	// version(4), length(20)
	ipv4[0] = byte(0x45)
	// TOS
	ipv4[1] = 0
	// total length
	binary.BigEndian.PutUint16(ipv4[2:4], uint16(28+len(payload)))
	// identification
	binary.BigEndian.PutUint16(ipv4[4:6], 0)
	// fragment offset (don't fragment)
	binary.BigEndian.PutUint16(ipv4[6:8], 0x4000)
	// TTL
	ipv4[8] = 255
	// protocol (17=UDP)
	ipv4[9] = 17
	// Checksum
	binary.BigEndian.PutUint16(ipv4[10:12], 0)
	// source IP
	binary.BigEndian.PutUint32(ipv4[12:16], ipSourceAddr)
	// dest IP
	binary.BigEndian.PutUint32(ipv4[16:20], ipDestAddr)
	// update checksum
	binary.BigEndian.PutUint16(ipv4[10:12], ipChecksum(ipv4))

	if PPCAP_DEBUG && (ipChecksum(ipv4) != 0) {
		panic("fail")
	}

	binary.BigEndian.PutUint16(udp[0:2], udpSourcePort)
	binary.BigEndian.PutUint16(udp[2:4], udpDestPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(payload)))
	binary.BigEndian.PutUint16(udp[6:8], 0)

	return w.appendPacket(headers, payload, packetReadTime, 0)
}

func (w *Writer) AppendPacket(packet []byte, packetReadTime int64, packetStreamIndex uint16) error {
	return w.appendPacket(nil, packet, packetReadTime, packetStreamIndex)
}

func (w *Writer) appendPacket(headers []byte, packet []byte, packetReadTime int64, packetStreamIndex uint16) error {
	if len(packet) > PPCAP_MAX_PACKET_SIZE {
		return errors.New("ppcap.Writer.AppendPacket: input exceeds PPCAP_MAX_PACKET_SIZE")
	}

	/*if PPCAP_DEBUG {
		fmt.Printf("Append packet: size = %v bytes\n", len(packet))
	}*/

	if len(headers) != w.hdrlay.ProtocolHeadersSize {
		// the writer needs to be set up with the correct layout to use this function
		panic("invalid usage")
	}

	packetLen := len(headers) + len(packet)
	bytesToAppend := packetLen + w.hdrlay.Size

	needDataFlush := (bytesToAppend > w.dataWriter.bufferAvail) ||
		((w.lastFlushTime != 0) && (packetReadTime > w.lastFlushTime+w.maxFlushIntervalNs))
	needBlockFlush := (w.currentBlockMsgCount+1 > w.maxMessagesPerBlock) ||
		/*(w.currentBlock.ByteCount+bytesToAppend > w.maxBytesPerBlock)*/
		(w.currentBlock.ByteCount > w.maxBytesPerBlock) // do it this way so that "large" packets don't cause us to flush a small block.

	if needBlockFlush || needDataFlush {
		if err := w.finishCurrentBlock(needDataFlush, packetReadTime); err != nil {
			return err
		}
	}

	// if this is the first packet in the block, initialize some block data
	if 0 == w.currentBlockMsgCount {
		/*if PPCAP_DEBUG {
			fmt.Printf("first message in block = sequence %v\n", w.messageSequence)
		}*/
		w.currentBlockHash.Reset()
		w.currentBlock.SeqNum = w.messageSequence
		w.currentBlock.Time = packetReadTime
		w.currentBlock.Position = w.dataWriter.bufferOffset + int64(w.dataWriter.bufferUsed)
	}

	// now append the payload
	buf, err := w.dataWriter.GetBuffer(bytesToAppend)
	if err != nil {
		return err
	}
	if w.hdrlay.Flags&HDRLAY_LIBPCAP > 0 {
		sec, ns := packetReadTime/1000000000, packetReadTime%1000000000
		binary.LittleEndian.PutUint32(buf[0:4], uint32(sec))
		binary.LittleEndian.PutUint32(buf[4:8], uint32(ns))
		binary.LittleEndian.PutUint32(buf[8:12], uint32(packetLen))
		binary.LittleEndian.PutUint32(buf[12:16], uint32(packetLen))
	} else {
		binary.LittleEndian.PutUint16(buf[0:2], uint16(packetLen))
		if w.hdrlay.Flags&HDRLAY_HAVE_STREAM_INDEX > 0 {
			offset := w.hdrlay.StreamIndexOffset
			binary.LittleEndian.PutUint16(buf[offset:2+offset], packetStreamIndex)
		}
	}
	copy(buf[w.hdrlay.Size:], headers)
	copy(buf[w.hdrlay.Size+len(headers):], packet)

	// append block stats
	w.currentBlockHash.Write(buf)
	w.currentBlockMsgCount += 1
	w.currentBlock.ByteCount += bytesToAppend

	w.messageSequence += 1

	return nil
}

func (w *Writer) finishCurrentBlock(flush bool, nowUnixNano int64) error {
	if 0 == w.currentBlockMsgCount {
		// nothing to do
		return nil
	}

	// allocate a new index entry (this may flush the index file)
	blockEntry, err := w.indexWriter.GetBuffer(sizeofIndexEntry)
	if err != nil {
		return err
	}

	// fill out the new entry
	hash := w.currentBlockHash.Sum64()

	binary.LittleEndian.PutUint64(blockEntry[0:8], hash)
	littleEndian_PutUint48(blockEntry[8:14], uint64(w.currentBlock.Position))
	littleEndian_PutUint48(blockEntry[14:20], uint64(w.currentBlock.SeqNum))
	binary.LittleEndian.PutUint32(blockEntry[20:24], uint32(w.currentBlock.ByteCount))
	binary.LittleEndian.PutUint64(blockEntry[24:32], uint64(w.currentBlock.Time))

	if PPCAP_DEBUG {
		totalSize := w.currentBlock.Position + int64(w.currentBlock.ByteCount)
		fmt.Printf("finished block (size=%v), total=%fMB\n", w.currentBlock.ByteCount, float64(totalSize)/(1024*1024))
	}

	if flush {
		if err := w.dataWriter.Flush(); err != nil {
			return err
		}
		if err := w.indexWriter.Flush(); err != nil {
			return err
		}
		w.lastFlushTime = nowUnixNano
	}

	// reset the current block
	w.currentBlock = BlockInfo{}
	w.currentBlockMsgCount = 0

	return nil
}

func (w *Writer) InitFlushTimer(nowUnixNano int64) {
	w.lastFlushTime = nowUnixNano
}

func (w *Writer) FlushTimer(nowUnixNano int64) error {
	if (w.currentBlockMsgCount > 0) &&
		(nowUnixNano > w.lastFlushTime+w.maxFlushIntervalNs) {
		if PPCAP_DEBUG {
			fmt.Println("Timed Flush")
		}
		return w.finishCurrentBlock(true, nowUnixNano)
	}
	return nil
}
