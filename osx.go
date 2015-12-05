// +build darwin

package gofi

import (
	"errors"
	"sync"
)

// DefaultInterfaceName returns the name of the default WiFi device on this machine.
// If the machine has no default WiFi device, this returns an error.
func DefaultInterfaceName() (string, error) {
	if res, ok := defaultOSXInterfaceName(); !ok {
		return "", errors.New("no WiFi devices found")
	} else {
		return res, nil
	}
}

// NewHandle creates a new handle with the given interface name.
// If the handle cannot be created for any reason (e.g., permissions, no such
// device, etc.), then this returns an error.
func NewHandle(interfaceName string) (Handle, error) {
	inter, err := newOSXInterface(interfaceName)
	if err != nil {
		return nil, err
	}

	bpf, err := newBpfHandle()
	if err != nil {
		return nil, err
	}

	if err := setupBpfHandle(bpf, interfaceName); err != nil {
		bpf.Close()
		return nil, err
	}

	return &osxHandle{osxInterface: inter, bpfHandle: bpf}, nil
}

func setupBpfHandle(handle *bpfHandle, iname string) error {
	if err := handle.SetReasonableBufferSize(); err != nil {
		return err
	}
	if err := handle.SetInterface(iname); err != nil {
		return err
	}
	if err := handle.SetupDataLink(); err != nil {
		return err
	}
	if err := handle.BecomePromiscuous(); err != nil {
		return err
	}
	if err := handle.SetImmediate(true); err != nil {
		return err
	}
	if err := handle.SetHeaderComplete(true); err != nil {
		return err
	}
	return nil
}

type readBufferNode struct {
	packet RadioPacket
	next   *readBufferNode
}

type osxHandle struct {
	bpfHandle *bpfHandle

	osxInterfaceLock sync.Mutex
	osxInterface     *osxInterface

	readLock        sync.Mutex
	readBufferFirst *readBufferNode
	readBufferLast  *readBufferNode

	writeLock sync.Mutex

	closeLock sync.Mutex
	closed    bool
}

func (h *osxHandle) Channel() int {
	h.osxInterfaceLock.Lock()
	defer h.osxInterfaceLock.Unlock()
	return h.osxInterface.Channel()
}

func (h *osxHandle) SetChannel(i int) error {
	h.osxInterfaceLock.Lock()
	defer h.osxInterfaceLock.Unlock()
	return h.osxInterface.SetChannel(i)
}

func (h *osxHandle) Receive() (Frame, *RadioInfo, error) {
	h.readLock.Lock()
	defer h.readLock.Unlock()

	if h.readBufferFirst == nil {
		packets, err := h.bpfHandle.ReceiveMany()
		if err != nil {
			return nil, nil, err
		}
		for _, packet := range packets {
			node := &readBufferNode{packet, nil}
			if h.readBufferFirst == nil {
				h.readBufferFirst = node
				h.readBufferLast = node
			} else {
				h.readBufferLast.next = node
				h.readBufferLast = node
			}
		}
	}

	node := h.readBufferFirst
	h.readBufferFirst = h.readBufferFirst.next
	if h.readBufferFirst == nil {
		h.readBufferLast = nil
	}
	return node.packet.Frame, node.packet.RadioInfo, nil
}

func (h *osxHandle) Send(f Frame) error {
	h.writeLock.Lock()
	defer h.writeLock.Unlock()
	return h.bpfHandle.Send(f)
}

func (h *osxHandle) Close() {
	h.closeLock.Lock()
	defer h.closeLock.Unlock()
	if h.closed {
		return
	}
	h.closed = true
	h.bpfHandle.Close()
}
