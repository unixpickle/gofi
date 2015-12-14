// +build darwin

package gofi

import (
	"encoding/binary"
	"errors"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

// These ioctl()s are used for Apple's 802.11 ioctl API,
// as shown in apple80211_ioctl.h.
const (
	ioctlSIOCSA80211 = 0x802869c8
	ioctlSIOCGA80211 = 0xc02869c9
)

// These are the commands used in Apple's 802.11 ioctl API.
const (
	a80211CmdChannel           = 4
	a80211CmdCardCapabilities  = 12
	a80211CmdDisassociate      = 22
	a80211CmdSupportedChannels = 27
)

const a80211MaxChannelCount = 64

// An osxInterface makes it possible to interact with Apple's 802.11
// ioctl API.
type osxInterface struct {
	fd   int
	name string
}

// defaultOSXInterfaceName returns the name of the default interface.
// If no interface exists, the ok value is set to false.
func defaultOSXInterfaceName() (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range interfaces {
		if i, err := newOSXInterface(iface.Name); err == nil {
			i.Disassociate()
			i.Close()
			return iface.Name, nil
		}
	}

	return "", errors.New("no WiFi devices found")
}

// newOSXInterface creates an interface given a name.
// This fails if the interface cannot be found or is not a WiFi device.
func newOSXInterface(name string) (*osxInterface, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if fd < 0 {
		return nil, err
	}
	iface := &osxInterface{fd, name}
	buf := make([]byte, 8)

	// NOTE: getting the capabilities is a simple way to make sure that the interface
	// exists and is a WiFi device.
	if err := iface.get(a80211CmdCardCapabilities, buf); err != nil {
		return nil, err
	}

	return iface, nil
}

// SupportedChannels generates an list of supported channels in
// an unspecified order.
func (iface *osxInterface) SupportedChannels() []Channel {
	resultData := make([]byte, 8+(a80211MaxChannelCount*12))
	if err := iface.get(a80211CmdSupportedChannels, resultData); err != nil {
		return []Channel{}
	}
	count := int(binary.LittleEndian.Uint32(resultData[4:]))
	if count > a80211MaxChannelCount {
		panic("channel overflow")
	}
	res := []Channel{}
	for i := 0; i < count; i++ {
		offset := 8 + 12*i
		res = append(res, decodeA80211ChannelDesc(resultData[offset:]))
	}
	return res
}

// Channel returns the interface's current channel number.
func (i *osxInterface) Channel() Channel {
	data := make([]byte, 16)
	if err := i.get(a80211CmdChannel, data); err != nil {
		return Channel{}
	}
	return decodeA80211ChannelDesc(data[4:])
}

// SetChannel switches to a channel.
func (iface *osxInterface) SetChannel(c Channel) error {
	if c.Width == 0 {
		c.Width = ChannelWidth20MHz
	}

	resultData := make([]byte, 8+(a80211MaxChannelCount*12))
	if err := iface.get(a80211CmdSupportedChannels, resultData); err != nil {
		return err
	}
	count := int(binary.LittleEndian.Uint32(resultData[4:]))
	if count > a80211MaxChannelCount {
		panic("channel overflow")
	}
	for i := 0; i < count; i++ {
		offset := 8 + 12*i
		ch := decodeA80211ChannelDesc(resultData[offset:])
		if ch == c {
			data := make([]byte, 16)

			binary.LittleEndian.PutUint32(data, 1)
			copy(data[4:], resultData[offset:])

			return iface.set(a80211CmdChannel, 0, data)
		}
	}
	return errors.New("unknown channel")
}

// Disassociate disconnects the interface from the current network.
// On El Capitan, it is usually necessary to disassociate before
// entering promiscuous mode.
func (i *osxInterface) Disassociate() {
	data := make([]byte, 12)
	i.set(a80211CmdDisassociate, 0, data)
}

// Close closes the interface socket.
// After you call this, you should not call anything else
// on the interface.
func (i *osxInterface) Close() {
	unix.Close(i.fd)
}

func (i *osxInterface) get(cmd int, data []byte) error {
	inStruct := make([]byte, 40+len(data))
	copy(inStruct[:16], []byte(i.name))
	binary.LittleEndian.PutUint32(inStruct[16:], uint32(cmd))
	binary.LittleEndian.PutUint32(inStruct[24:], uint32(len(data)))
	if err := i.ioctlWithData(ioctlSIOCGA80211, inStruct); err != nil {
		return err
	}
	copy(data, inStruct[40:])
	return nil
}

func (i *osxInterface) set(cmd int, val int, data []byte) error {
	inStruct := make([]byte, 40+len(data))
	copy(inStruct[:16], []byte(i.name))
	binary.LittleEndian.PutUint32(inStruct[16:], uint32(cmd))
	binary.LittleEndian.PutUint32(inStruct[20:], uint32(val))
	binary.LittleEndian.PutUint32(inStruct[24:], uint32(len(data)))
	copy(inStruct[40:], data)
	if err := i.ioctlWithData(ioctlSIOCSA80211, inStruct); err != nil {
		return err
	}
	return nil
}

func (i *osxInterface) ioctlWithData(command int, data []byte) error {
	unsafeData := unsafe.Pointer(&data[0])
	binary.LittleEndian.PutUint64(data[32:], uint64(uintptr(unsafeData)+40))

	_, _, err := unix.Syscall(unix.SYS_IOCTL, uintptr(i.fd), uintptr(command),
		uintptr(unsafeData))

	if err != 0 {
		return err
	} else {
		return nil
	}
}

func decodeA80211ChannelDesc(desc []byte) Channel {
	var ch Channel
	ch.Width = ChannelWidth20MHz
	ch.Number = int(binary.LittleEndian.Uint32(desc[4:]))

	flags := binary.LittleEndian.Uint32(desc[8:])
	if (flags & (1 << 2)) != 0 {
		ch.Width = ChannelWidth40MHz
	}
	return ch
}
