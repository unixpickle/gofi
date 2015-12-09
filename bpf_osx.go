// +build darwin

package gofi

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
	"strconv"
	"syscall"
	"time"
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

// ioctlBIOCIMMEDIATE is an ioctl command used to enable "immediate mode"
// on a BPF device.
// When immediate mode is enabled, packets are not buffered during reads,
// letting the application process incoming packets faster.
const ioctlBIOCIMMEDIATE = 0x80044270

// ioctlBIOCSHDRCMPLT is an ioctl command used to toggle "header complete"
// on a BPF device.
// When header complete is enabled, source MACs can be forged.
const ioctlBIOCSHDRCMPLT = 0x80044275

// ioctlBIOCSRTIMEOUT is an ioctl command used to set the read timeout
// on a BPF device.
const ioctlBIOCSRTIMEOUT = 0x8010426d

// ioctlIntegerSize is the number of bytes to use for integers before
// safely passing them to ioctl calls.
// Who knows when 128-bit processors will come out, but by then I'm sure
// most of this code will be broken anyway.
const ioctlIntegerSize = 8

// dltIEEE802_11_RADIO is a data-link type for ioctlBIOCSDLT.
// Read more here:
// http://www.opensource.apple.com/source/tcpdump/tcpdump-16/tcpdump/ieee802_11_radio.h
const dltIEEE802_11_RADIO = 127

// dltIEEE802_11 is a data-link type for ioctlBIOCSDLT.
// This data-link type captures 802.11 headers with no extra info.
const dltIEEE802_11 = 105

var errBPFReadTimeout = errors.New("BPF read timeout exceeded")

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

// Close closes the underlying socket.
// You should not call this while any send or receive operations are taking place.
// After closing the handle, you should not call any other methods on it.
func (b *bpfHandle) Close() error {
	return unix.Close(b.fd)
}

// SetReadBufferSize sets the read buffer size on the handle.
// You must call this before calling SetInterface() if you wish to read from the device.
// This will return an error if the OS does not support the given buffer size.
func (b *bpfHandle) SetReadBufferSize(size int) error {
	if ok, err := b.ioctlWithInt(ioctlBIOCSBLEN, size); !ok {
		return err
	}

	numData := make([]byte, ioctlIntegerSize)
	b.ioctlWithData(ioctlBIOCGBLEN, numData)
	if binary.LittleEndian.Uint32(numData) < uint32(size) {
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
	// NOTE: I chose 128 bytes in order to be extremely cautious.
	// Currently on OS X (10.11), the ifreq structure is only 32 bytes.
	data := make([]byte, 128)
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
	if ok, _ := b.ioctlWithInt(ioctlBIOCSDLT, dltIEEE802_11_RADIO); ok {
		b.dataLinkType = dltIEEE802_11_RADIO
		return nil
	}
	if ok, _ := b.ioctlWithInt(ioctlBIOCSDLT, dltIEEE802_11); ok {
		b.dataLinkType = dltIEEE802_11
		return nil
	}
	return errors.New("could not use an 802.11 data-link type")
}

// BecomePromiscuous enters promiscuous mode.
// For more, see BIOCPROMISC at https://www.freebsd.org/cgi/man.cgi?bpf(4)
func (b *bpfHandle) BecomePromiscuous() error {
	if ok, err := b.ioctlWithData(ioctlBIOCPROMISC, nil); ok {
		return nil
	} else {
		return err
	}
}

// SetImmediate enables or disables immediate mode.
// While immediate mode is enabled, reads will return as soon as a
// packet is available.
func (b *bpfHandle) SetImmediate(flag bool) error {
	num := 0
	if flag {
		num = 1
	}
	if ok, err := b.ioctlWithInt(ioctlBIOCIMMEDIATE, num); ok {
		return nil
	} else {
		return err
	}
}

// SetReadTimeout sets the amount of time before a ReceiveMany will fail with
// errBPFReadTimeout.
func (b *bpfHandle) SetReadTimeout(d time.Duration) error {
	value := make([]byte, 16)
	binary.LittleEndian.PutUint64(value, uint64(d/time.Second))
	binary.LittleEndian.PutUint64(value[8:], uint64((d%time.Second)/time.Microsecond))
	if ok, err := b.ioctlWithData(ioctlBIOCSRTIMEOUT, value); ok {
		return nil
	} else {
		return err
	}
}

// SetHeaderComplete toggles the "header complete" option.
// When this option is enabled, link-level addresses (i.e. MACs) can be spoofed.
// You should probably enable header complete mode before your first Send().
func (b *bpfHandle) SetHeaderComplete(flag bool) error {
	num := 0
	if flag {
		num = 1
	}
	if ok, err := b.ioctlWithInt(ioctlBIOCSHDRCMPLT, num); ok {
		return nil
	} else {
		return err
	}
}

// ReceiveMany receives one or more packets, parses them, and returns them.
// If the read fails or if the packets cannot be parsed, this returns an error.
func (b *bpfHandle) ReceiveMany() ([]RadioPacket, error) {
	for {
		amount, err := unix.Read(b.fd, b.readBuffer)
		if err == unix.EINTR {
			continue
		} else if err == unix.ENXIO {
			return nil, errors.New("device is down")
		} else if err == unix.ETIMEDOUT || amount == 0 {
			return nil, errBPFReadTimeout
		} else if err != nil {
			return nil, err
		}
		return b.parsePackets(b.readBuffer[:amount])
	}
}

// Send writes a packet to the handle.
func (b *bpfHandle) Send(frame Frame) error {
	sendData := frame

	if b.dataLinkType == dltIEEE802_11_RADIO {
		sendData = encodeRadiotapPacket(frame)
	}

	// NOTE: although dltIEEE802_11 doesn't give us checksums when receiving,
	// it still expects checksums when we send. What a greedy snake!

	if n, err := unix.Write(b.fd, sendData); err != nil {
		return err
	} else if n < len(frame) {
		return errors.New("full packet was not sent")
	} else {
		return nil
	}
}

func (b *bpfHandle) parsePackets(data []byte) ([]RadioPacket, error) {
	if len(data) == 0 {
		return nil, ErrBufferUnderflow
	}

	res := make([]RadioPacket, 0, 1)

	for i := 0; i < len(data)-18; i = align4(i) {
		// Parse the bpf_xhdr, as defined in https://www.freebsd.org/cgi/man.cgi?bpf(4).
		// For some reason, on OS X, this header seems to use 64-bits total for the timestamp.
		capturedLength := int(binary.LittleEndian.Uint32(data[i+8:]))
		originalLength := int(binary.LittleEndian.Uint32(data[i+12:]))
		headerLength := int(binary.LittleEndian.Uint16(data[i+16:]))

		// NOTE: if the sizes were greater than 1<<31, casting them to integers
		// might make them negative. If a size is bigger than int's max value,
		// then there's no way our buffer can fit it.
		if capturedLength < 0 || originalLength < 0 ||
			i+headerLength+capturedLength > len(data) {
			return nil, ErrBufferUnderflow
		}

		packetData := data[i+headerLength : i+headerLength+capturedLength]
		if p, err := b.parsePacket(packetData); err != nil {
			return nil, err
		} else {
			res = append(res, *p)
		}

		i += headerLength + capturedLength
	}

	return res, nil
}

func (b *bpfHandle) parsePacket(data []byte) (*RadioPacket, error) {
	if b.dataLinkType == dltIEEE802_11 {
		// NOTE: we must add a checksum, because all Frames have checksums.
		checksum := crc32.ChecksumIEEE(data)
		frame := make(Frame, len(data)+4)
		copy(frame, data)
		binary.LittleEndian.PutUint32(frame[len(data):], checksum)
		return &RadioPacket{frame, nil}, nil
	} else if b.dataLinkType == dltIEEE802_11_RADIO {
		return parseRadiotapPacket(data)
	} else {
		return nil, errors.New("invalid data-link type")
	}
}

func (b *bpfHandle) ioctlWithData(command int, data []byte) (ok bool, err syscall.Errno) {
	if data != nil {
		_, _, err = unix.Syscall(unix.SYS_IOCTL, uintptr(b.fd), uintptr(command),
			uintptr(unsafe.Pointer(&data[0])))
	} else {
		_, _, err = unix.Syscall(unix.SYS_IOCTL, uintptr(b.fd), uintptr(command), uintptr(0))
	}
	if err != 0 {
		return
	} else {
		return true, 0
	}
}

func (b *bpfHandle) ioctlWithInt(command, argument int) (ok bool, err syscall.Errno) {
	numData := make([]byte, ioctlIntegerSize)
	binary.LittleEndian.PutUint32(numData, uint32(argument))
	return b.ioctlWithData(command, numData)
}

func align4(i int) int {
	if (i & 3) == 0 {
		return i
	} else {
		return i + 4 - (i & 3)
	}
}
