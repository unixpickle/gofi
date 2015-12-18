package gofi

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
)

type radiotapFieldInfo struct {
	Alignment int
	Size      int
}

// radiotapFields stores the alignment and size of every radiotap data field, as specified
// in http://www.opensource.apple.com/source/tcpdump/tcpdump-16/tcpdump/ieee802_11_radio.h.
// This information makes it possible to walk through the fields.
var radiotapFields []radiotapFieldInfo = []radiotapFieldInfo{
	{8, 8},
	{1, 1},
	{1, 1},
	{2, 4},
	{2, 2},
	{1, 1},
	{1, 1},
	{2, 2},
	{2, 2},
	{2, 2},
	{1, 1},
	{1, 1},
	{1, 1},
	{1, 1},
}

const (
	radiotapFlags         = 1
	radiotapRate          = 2
	radiotapChannel       = 3
	radiotapSignalPower   = 5
	radiotapNoisePower    = 6
	radiotapTransmitPower = 10
)

// These are some radiotap flags, taken from http://www.radiotap.org/defined-fields/Flags.
const (
	radiotapFlagHasFCS     = 0x10
	radiotapFlagHasPadding = 0x20
)

func parseRadiotapPacket(data []byte) (*RadioPacket, error) {
	if len(data) < 8 {
		return nil, ErrBufferUnderflow
	}

	headerSize := int(binary.LittleEndian.Uint16(data[2:]))
	if len(data) < headerSize || headerSize < 8 {
		return nil, ErrBufferUnderflow
	}

	presentFlags := binary.LittleEndian.Uint32(data[4:])
	dataFields := data[8:headerSize]
	if (presentFlags & 0x80000000) != 0 {
		if len(data) < 12 || headerSize < 12 {
			return nil, ErrBufferUnderflow
		}
		dataFields = data[12:headerSize]
	}

	var radioInfo RadioInfo
	var fieldOffset int
	var flags int
	for i, info := range radiotapFields {
		if (presentFlags & (1 << uint(i))) == 0 {
			continue
		}
		if (fieldOffset & (info.Alignment - 1)) != 0 {
			fieldOffset += info.Alignment - (fieldOffset & (info.Alignment - 1))
		}
		if fieldOffset+info.Size > len(dataFields) {
			return nil, ErrBufferUnderflow
		}
		switch i {
		case radiotapFlags:
			flags = int(dataFields[fieldOffset])
		case radiotapRate:
			radioInfo.Rate = DataRate(dataFields[fieldOffset])
		case radiotapChannel:
			radioInfo.Frequency = int(binary.LittleEndian.Uint16(dataFields[fieldOffset:]))
		case radiotapNoisePower:
			radioInfo.NoisePower = int(int8(dataFields[fieldOffset]))
		case radiotapSignalPower:
			radioInfo.SignalPower = int(int8(dataFields[fieldOffset]))
		case radiotapTransmitPower:
			radioInfo.TransmitPower = int(int8(dataFields[fieldOffset]))
		}
		fieldOffset += info.Size
	}

	frame := Frame(data[headerSize:])

	if (flags & radiotapFlagHasPadding) != 0 {
		return nil, errors.New("radiotap frame padding is unsupported")
	}

	// Add a checksum if one was not present, since all Frames must have checksums.
	if (flags & radiotapFlagHasFCS) == 0 {
		checksum := crc32.ChecksumIEEE(frame)
		newFrame := make([]byte, len(frame)+4)
		copy(newFrame, frame)
		binary.LittleEndian.PutUint32(newFrame[len(frame):], checksum)
		frame = newFrame
	}

	return &RadioPacket{frame, &radioInfo}, nil
}

// encodeRadiotapPacket generates a radiotap buffer which contains a Frame.
func encodeRadiotapPacket(f Frame, r DataRate) []byte {
	// Generate a radiotap header with the data rate and the checksum flag.
	header := []byte{0, 0, 10, 0, (1 << radiotapFlags) | (1 << radiotapRate), 0, 0, 0,
		radiotapFlagHasFCS, byte(r)}
	return append(header, f...)
}
