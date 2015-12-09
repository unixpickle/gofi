// Package gofi provides a super simple API for sending and receiving data-link packets over WiFi.
package gofi

type ChannelWidth int

const (
	ChannelWidthUnknown = iota
	ChannelWidth20MHz
	ChannelWidth40MHz
)

// NewChannelWidthMegahertz creates a ChannelWidth which represents
// the provided number of megahertz.
// This currently supports 20 and 40 MHz, and nothing else.
func NewChannelWidthMegahertz(mhz int) ChannelWidth {
	switch mhz {
	case 20:
		return ChannelWidth20MHz
	case 40:
		return ChannelWidth40MHz
	default:
		return ChannelWidthUnknown
	}
}

// Megahertz returns the approximate number of megahertz represented
// by this channel width.
func (w ChannelWidth) Megahertz() int {
	return map[ChannelWidth]int{
		ChannelWidth20MHz: 20,
		ChannelWidth40MHz: 40,
	}[w]
}

// A Channel specifies information about a WiFi channel's frequency range.
type Channel struct {
	Number int
	Width  ChannelWidth
}

// A Handle facilitates raw WiFi interactions like packet injection,
// sniffing, and channel hopping.
type Handle interface {
	// SupportedChannels returns a list of supported WLAN channels.
	SupportedChannels() []Channel

	// Channel gets the WLAN channel to which the device is tuned.
	Channel() Channel

	// SetChannel tunes the device into a given WLAN channel.
	SetChannel(Channel) error

	// Receive reads the next packet from the device.
	// The returned RadioInfo will be nil if the device does not
	// support radio information.
	Receive() (Frame, *RadioInfo, error)

	// Send sends a packet over the device.
	Send(Frame) error

	// Close closes the handle.
	// You should always close a Handle once you are done with it.
	Close()
}
