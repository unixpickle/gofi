package gofi

type Handle interface {
	// Channel gets the current WiFi channel number to which the
	// device is tuned.
	Channel() int

	// SetChannel tunes the device into a given WiFi channel.
	SetChannel(int) error

	// Receive reads the next packet from the device.
	Receive() (Frame, *RadioInfo, error)

	// Send sends a packet over the device.
	Send(Frame) error

	// Close closes the handle.
	// You should always close a Handle after being done with it.
	Close()
}
