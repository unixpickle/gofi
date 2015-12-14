// +build darwin

package gofi

import (
	"sync"
	"time"
)

// DefaultInterfaceName returns the name of the default WiFi device on this machine.
// If the machine has no default WiFi device, this returns an error.
func DefaultInterfaceName() (string, error) {
	return defaultOSXInterfaceName()
}

// NewHandle creates a new handle with the given interface name.
// If the handle cannot be created for any reason (e.g., permissions, no such
// device, etc.), then this returns an error.
func NewHandle(interfaceName string) (Handle, error) {
	inter, err := newOSXInterface(interfaceName)
	if err != nil {
		return nil, err
	}

	// NOTE: on El Capitan it seems that you must do this before entering promiscuous
	// mode to get channel switching to work correctly.
	inter.Disassociate()

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
	if err := handle.SetReadTimeout(time.Second); err != nil {
		return err
	}
	return nil
}

type readBufferNode struct {
	packet RadioPacket
	next   *readBufferNode
}

type osxHandle struct {
	bpfHandleLock sync.RWMutex
	bpfHandle     *bpfHandle

	osxInterfaceLock sync.Mutex
	osxInterface     *osxInterface

	receiveLock     sync.Mutex
	readBufferFirst *readBufferNode
	readBufferLast  *readBufferNode

	sendLock sync.Mutex
}

func (h *osxHandle) SupportedChannels() []Channel {
	h.osxInterfaceLock.Lock()
	defer h.osxInterfaceLock.Unlock()
	if h.osxInterface == nil {
		return []Channel{}
	} else {
		return h.osxInterface.SupportedChannels()
	}
}

func (h *osxHandle) Channel() Channel {
	h.osxInterfaceLock.Lock()
	defer h.osxInterfaceLock.Unlock()
	if h.osxInterface == nil {
		return Channel{}
	} else {
		return h.osxInterface.Channel()
	}
}

func (h *osxHandle) SetChannel(ch Channel) error {
	h.osxInterfaceLock.Lock()
	defer h.osxInterfaceLock.Unlock()
	if h.osxInterface == nil {
		return ErrClosed
	} else {
		return h.osxInterface.SetChannel(ch)
	}
}

func (h *osxHandle) Receive() (Frame, *RadioInfo, error) {
	h.receiveLock.Lock()
	defer h.receiveLock.Unlock()

	if h.readBufferFirst == nil {
		if err := h.populateReadBuffer(); err != nil {
			return nil, nil, err
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
	h.sendLock.Lock()
	defer h.sendLock.Unlock()

	h.bpfHandleLock.RLock()
	defer h.bpfHandleLock.RUnlock()

	if h.bpfHandle != nil {
		return h.bpfHandle.Send(f)
	} else {
		return ErrClosed
	}
}

func (h *osxHandle) Close() {
	h.bpfHandleLock.Lock()
	h.bpfHandle.Close()
	h.bpfHandle = nil
	h.bpfHandleLock.Unlock()

	h.osxInterfaceLock.Lock()
	h.osxInterface.Close()
	h.osxInterface = nil
	h.osxInterfaceLock.Unlock()
}

// populateReadBuffer reads more packets from the handle.
// The caller must be holding h.receiveLock.
func (h *osxHandle) populateReadBuffer() error {
	for {
		h.bpfHandleLock.RLock()
		if h.bpfHandle == nil {
			h.bpfHandleLock.RUnlock()
			return ErrClosed
		}
		packets, err := h.bpfHandle.ReceiveMany()
		h.bpfHandleLock.RUnlock()

		if err == errBPFReadTimeout {
			continue
		} else if err != nil {
			return err
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

		return nil
	}
}
