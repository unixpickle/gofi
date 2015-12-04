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

type bpfHandle int

func newBpfHandle() (bpfHandle, error) {
	res, err := unix.Open("/dev/bpf", 0, 0)
	if err == nil {
		return bpfHandle(res), nil
	} else if err == unix.EACCES {
		return 0, errors.New("permissions denied for: /dev/bpf")
	}
	i := 0
	for {
		devName := "/dev/bpf" + strconv.Itoa(i)
		res, err := unix.Open(devName, 0, 0)
		if err == nil {
			return bpfHandle(res), nil
		} else if err == unix.EACCES {
			return 0, errors.New("permissions denied for: " + devName)
		} else if err != unix.EBUSY {
			return 0, err
		}
		i++
	}
}

// SetInterface assigns an interface name to the BPF handle.
func (b bpfHandle) SetInterface(name string) error {
	data := make([]byte, 100)
	copy(data, []byte(name))
	_, err := b.ioctlWithData(ioctlBIOCSETIF, data)
	if err == unix.ENXIO {
		return errors.New("no such device: " + name)
	} else if err == unix.ENETDOWN {
		return errors.New("interface is down: " + name)
	}
	return err
}

func (b bpfHandle) ioctlWithData(command int, data []byte) (int, syscall.Errno) {
	r, _, err := unix.Syscall(unix.SYS_IOCTL, uintptr(b), uintptr(command),
		uintptr(unsafe.Pointer(&data[0])))
	return int(r), err
}
