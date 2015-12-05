package gofi

// Frame represents an 802.11 frame (with an included checksum).
type Frame []byte

// RadioInfo contains supplemental information that some hardware supports.
// Any unavailable fields will be set to 0.
type RadioInfo struct {
	// Frequency is the center frequency of the channel, measured in MHz.
	Frequency int

	// NoisePower is the noise power in dBm.
	NoisePower int

	// SignalPower is the signal power in dBm.
	SignalPower int

	// TransmitPower is the absolute transmit power in dBm for the antenna port.
	// More info can be found here under IEEE80211_RADIOTAP_DBM_TX_POWER:
	// http://www.opensource.apple.com/source/tcpdump/tcpdump-16/tcpdump/ieee802_11_radio.h
	TransmitPower int
}

type RadioPacket struct {
	Frame     Frame
	RadioInfo *RadioInfo
}
