package ppcap

import (
	"errors"
	"os"
)

type BufferedWriter struct {
	bufferOffset int64
	bufferUsed   int
	bufferAvail  int
	buf          []byte
	fd           *os.File
}

func NewBufferedWriter(fd *os.File, bufferByteCount int) (*BufferedWriter, error) {
	off, err := fd.Seek(0, os.SEEK_END)
	if err != nil {
		return nil, err
	}

	return &BufferedWriter{
		off,
		0,
		bufferByteCount,
		make([]byte, bufferByteCount),
		fd}, nil
}

func (io *BufferedWriter) Flush() error {
	if 0 == io.bufferUsed {
		return nil
	}
	if _, err := io.fd.WriteAt(io.buf[:io.bufferUsed], io.bufferOffset); err != nil {
		return err
	}
	if err := io.fd.Sync(); err != nil {
		return err
	}
	io.bufferOffset += int64(io.bufferUsed)
	io.bufferAvail = len(io.buf)
	io.bufferUsed = 0
	return nil
}

func (io *BufferedWriter) GetBuffer(byteCount int) ([]byte, error) {
	if byteCount > len(io.buf) {
		return nil, errors.New("ppcap.BufferedWriter.GetBuffer: requested size exceeds maximum")
	}

	if byteCount > io.bufferAvail {
		if err := io.Flush(); err != nil {
			return nil, err
		}
	}

	buf := io.buf[io.bufferUsed : io.bufferUsed+byteCount]
	io.bufferAvail -= byteCount
	io.bufferUsed += byteCount

	return buf, nil
}
