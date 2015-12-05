package gofi

import "encoding/binary"

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
	radiotapChannel       = 3
	radiotapSignalPower   = 5
	radiotapNoisePower    = 6
	radiotapTransmitPower = 10
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

	macPacket, err := ParseMACPacket(data[headerSize:])
	if err != nil {
		return nil, err
	}

	return &RadioPacket{*macPacket, &radioInfo}, nil
}
