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

// SetReadBufferSize sets the read buffer size on the handle.
// You must call this before SetInterface() if you wish to read from the device.
func (b *bpfHandle) SetReadBufferSize(size int) error {
	numData := make([]byte, 16)
	numData[0] = byte(size)
	numData[1] = byte(size >> 8)
	numData[2] = byte(size >> 16)
	numData[3] = byte(size >> 24)

	if ok, err := b.ioctlWithData(ioctlBIOCSBLEN, numData); !ok {
		return err
	}

	b.readBuffer = make([]byte, size)
	return nil
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
