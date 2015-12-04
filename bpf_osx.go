// +build darwin
package gofi

import (
	"errors"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ioctlBIOCSETIF is an ioctl command used for setting the network interface
// on a BPF device.
const ioctlBIOCSETIF = 0x8020426c

// ioctlBIOCSDLT is an ioctl command used for setting the data-link type
// on a BPF device.
const ioctlBIOCSDLT = 0x80044278

// ioctlBIOCPROMISC is an ioctl command used to enter promiscuous mode
// on a BPF device.
const ioctlBIOCPROMISC = 0x20004269

// ioctlBIOCSBLEN is an ioctl command used to set the read buffer size
// on a BPF device.
const ioctlBIOCSBLEN = 0xc0044266

// ioctlBIOCGBLEN is an ioctl command used to get the read buffer size
// on a BPF device.
const ioctlBIOCGBLEN = 0x40044266

// dltIEEE802_11_RADIO is a data-link type for ioctlBIOCSDLT.
// Read more here:
// http://www.opensource.apple.com/source/tcpdump/tcpdump-16/tcpdump/ieee802_11_radio.h
const dltIEEE802_11_RADIO = 127

// dltIEEE802_11 is a data-link type for ioctlBIOCSDLT.
// This data-link type captures 802.11 headers with no extra info.
const dltIEEE802_11 = 105

type bpfHandle struct {
	fd           int
	dataLinkType int
	readBuffer   []byte
}

func newBpfHandle() (*bpfHandle, error) {
	res, err := unix.Open("/dev/bpf", unix.O_RDWR, 0)
	if err == nil {
		return &bpfHandle{fd: res}, nil
	} else if err == unix.EACCES {
		return nil, errors.New("permissions denied for: /dev/bpf")
	}
	i := 0
	for {
		devName := "/dev/bpf" + strconv.Itoa(i)
		res, err := unix.Open(devName, unix.O_RDWR, 0)
		if err == nil {
			return &bpfHandle{fd: res}, nil
		} else if err == unix.EACCES {
			return nil, errors.New("permissions denied for: " + devName)
		} else if err != unix.EBUSY {
			return nil, err
		}
		i++
	}
}

// Close closes the underlying socket, terminating all send and receive operations.
func (b *bpfHandle) Close() error {
	return unix.Close(b.fd)
}

// SetReadBufferSize sets the read buffer size on the handle.
// You must call this before calling SetInterface() if you wish to read from the device.
// This will return an error if the OS does not support the given buffer size.
func (b *bpfHandle) SetReadBufferSize(size int) error {
	numData := make([]byte, 16)
	numData[0] = byte(size)
	numData[1] = byte(size >> 8)
	numData[2] = byte(size >> 16)
	numData[3] = byte(size >> 24)

	if ok, err := b.ioctlWithData(ioctlBIOCSBLEN, numData); !ok {
		return err
	}

	b.ioctlWithData(ioctlBIOCGBLEN, numData)
	if decodeInt32(numData) < size {
		return errors.New("unsupported buffer size")
	}

	b.readBuffer = make([]byte, size)
	return nil
}

// SetReasonableBufferSize uses SetReadBufferSize() to negotiate a buffer size with the OS.
func (b *bpfHandle) SetReasonableBufferSize() error {
	// NOTE: on my Macbook Pro, 0x80000 was the biggest supported buffer size.
	size := 0x80000
	for size > 0 {
		if b.SetReadBufferSize(size) == nil {
			return nil
		}
		size >>= 1
	}
	return errors.New("could not negotiate a buffer size")
}

// SetInterface assigns an interface name to the BPF handle.
func (b *bpfHandle) SetInterface(name string) error {
	data := make([]byte, 100)
	copy(data, []byte(name))
	if ok, err := b.ioctlWithData(ioctlBIOCSETIF, data); ok {
		return nil
	} else if err == unix.ENXIO {
		return errors.New("no such device: " + name)
	} else if err == unix.ENETDOWN {
		return errors.New("interface is down: " + name)
	} else {
		return err
	}
}

// SetupDataLink switches to a data-link type that provides raw 802.11 headers.
// If no 802.11 DLT is supported on the interface, this returns an error.
func (b *bpfHandle) SetupDataLink() error {
	numBuf := make([]byte, 16)
	numBuf[0] = dltIEEE802_11_RADIO
	if ok, _ := b.ioctlWithData(ioctlBIOCSDLT, numBuf); ok {
		b.dataLinkType = dltIEEE802_11_RADIO
		return nil
	}
	numBuf[0] = dltIEEE802_11
	if ok, _ := b.ioctlWithData(ioctlBIOCSDLT, numBuf); ok {
		b.dataLinkType = dltIEEE802_11
		return nil
	}
	return errors.New("could not use an 802.11 data-link type")
}

// BecomePromiscuous enters promiscuous mode.
// For more, see BIOCPROMISC at https://www.freebsd.org/cgi/man.cgi?bpf(4)
func (b *bpfHandle) BecomePromiscuous() error {
	if ok, err := b.ioctlWithInt(ioctlBIOCPROMISC, 0); ok {
		return nil
	} else {
		return err
	}
}

// Receive reads one or more packets from the handle and returns them.
func (b *bpfHandle) Receive() ([]Packet, error) {
	for {
		amount, err := unix.Read(b.fd, b.readBuffer)
		if err == unix.EINTR {
			continue
		} else if err == unix.ENXIO {
			return nil, errors.New("device is down")
		} else if err != nil {
			return nil, err
		}
		return b.parsePackets(b.readBuffer[:amount])
	}
}

func (b *bpfHandle) parsePackets(data []byte) ([]Packet, error) {
	if len(data) == 0 {
		return nil, ErrBufferUnderflow
	}
	res := make([]Packet, 0, 1)

	for i := 0; i < len(data)-18; i = align4(i) {
		// Parse the bpf_xhdr, as defined in https://www.freebsd.org/cgi/man.cgi?bpf(4).
		// For some reason, on OS X, this header seems to use 64-bits total for the timestamp.
		capturedLength := decodeInt32(data[i+8:])
		originalLength := decodeInt32(data[i+12:])
		headerLength := decodeInt16(data[i+16:])

		if i+headerLength+capturedLength > len(data) {
			return nil, ErrBufferUnderflow
		}

		packetData := data[i+headerLength : i+headerLength+capturedLength]
		if packet, err := b.parsePacket(packetData, originalLength); err != nil {
			return nil, err
		} else {
			res = append(res, *packet)
		}
		i += headerLength + capturedLength
	}

	return res, nil
}

func (b *bpfHandle) parsePacket(data []byte, origLen int) (*Packet, error) {
	if b.dataLinkType == dltIEEE802_11 {
		if mac, err := ParseMACPacket(data); err != nil {
			return nil, err
		} else {
			return &Packet{MACPacket: *mac}, nil
		}
	} else if b.dataLinkType == dltIEEE802_11_RADIO {
		return parseRadioPacket(data)
	}
	return nil, errors.New("unsupported data-link type")
}

func (b *bpfHandle) ioctlWithData(command int, data []byte) (ok bool, err syscall.Errno) {
	_, _, err = unix.Syscall(unix.SYS_IOCTL, uintptr(b.fd), uintptr(command),
		uintptr(unsafe.Pointer(&data[0])))
	if err != 0 {
		return
	} else {
		return true, 0
	}
}

func (b *bpfHandle) ioctlWithInt(command, argument int) (ok bool, err syscall.Errno) {
	_, _, err = unix.Syscall(unix.SYS_IOCTL, uintptr(b.fd), uintptr(command), uintptr(argument))
	if err != 0 {
		return
	} else {
		return true, 0
	}
}

func parseRadioPacket(data []byte) (*Packet, error) {
	// TODO: parse the radio header to get power information.

	if len(data) < 4 {
		return nil, ErrBufferUnderflow
	}

	headerSize := decodeInt16(data[2:4])
	if len(data) < headerSize {
		return nil, ErrBufferUnderflow
	}

	macPacket, err := ParseMACPacket(data[headerSize:])
	if err != nil {
		return nil, err
	}
	return &Packet{MACPacket: *macPacket}, nil
}

func align4(i int) int {
	if (i & 3) == 0 {
		return i
	} else {
		return i + 4 - (i & 3)
	}
}

func decodeInt16(bytes []byte) int {
	return int(bytes[0]) | (int(bytes[1]) << 8)
}

func decodeInt32(bytes []byte) int {
	return int(bytes[0]) | (int(bytes[1]) << 8) | (int(bytes[2]) << 16) | (int(bytes[3]) << 24)
}
