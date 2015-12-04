package gofi

type RadioInfo struct {
	NoisePower    int
	SignalPower   int
	TransmitPower int
}

type MACPacket struct {
	// TODO: some fields here.
}

// ParseMACPacket decodes a MAC packet.
func ParseMACPacket(data []byte) (*MACPacket, error) {
	// TODO: this.
	return &MACPacket{}, nil
}

type Packet struct {
	MACPacket
	RadioInfo *RadioInfo
}
