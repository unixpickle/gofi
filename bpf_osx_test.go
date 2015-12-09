// +build darwin

package gofi

import (
	"testing"
	"time"
)

func TestSetInterface(t *testing.T) {
	name, ok := defaultOSXInterfaceName()
	if !ok {
		t.Fatal("no default interface")
	}
	handle, err := newBpfHandle()
	if err != nil {
		t.Fatal("could not open handle:", err)
	}
	defer handle.Close()
	if err := handle.SetInterface(name); err != nil {
		t.Error("failed to set interface to: "+name+":", err)
	}
	if handle.SetInterface("foobar") == nil {
		t.Error("successfully set interface to: foobar")
	}
}

func TestSetupDataLink(t *testing.T) {
	name, ok := defaultOSXInterfaceName()
	if !ok {
		t.Fatal("no default interface")
	}
	handle, err := newBpfHandle()
	if err != nil {
		t.Fatal("could not open handle:", err)
	}
	defer handle.Close()
	if err := handle.SetInterface(name); err != nil {
		t.Fatal("failed to set interface to: "+name+":", err)
	}
	if err := handle.SetupDataLink(); err != nil {
		t.Error("failed to setup data link:", err)
	}
}

func TestBecomePromiscuous(t *testing.T) {
	name, ok := defaultOSXInterfaceName()
	if !ok {
		t.Fatal("no default interface")
	}
	handle, err := newBpfHandle()
	if err != nil {
		t.Fatal("could not open handle:", err)
	}
	defer handle.Close()
	if err := handle.SetInterface(name); err != nil {
		t.Fatal("failed to set interface to: "+name+":", err)
	}
	if err := handle.BecomePromiscuous(); err != nil {
		t.Error("failed to become promiscuous:", err)
	}
}

func TestSetReadBufferSize(t *testing.T) {
	name, ok := defaultOSXInterfaceName()
	if !ok {
		t.Fatal("no default interface")
	}
	handle, err := newBpfHandle()
	if err != nil {
		t.Fatal("could not open handle:", err)
	}
	defer handle.Close()
	if err := handle.SetReadBufferSize(0x100); err != nil {
		t.Fatal("failed to set read buffer size:", err)
	}
	if err := handle.SetInterface(name); err != nil {
		t.Fatal("failed to set interface to: "+name+":", err)
	}
}

func TestReceiveMany(t *testing.T) {
	name, ok := defaultOSXInterfaceName()
	if !ok {
		t.Fatal("no default interface")
	}
	handle, err := newBpfHandle()
	if err != nil {
		t.Fatal("could not open handle:", err)
	}
	defer handle.Close()
	if err := handle.SetReadBufferSize(0x1000); err != nil {
		t.Fatal("failed to set read buffer size:", err)
	}
	if err := handle.SetInterface(name); err != nil {
		t.Fatal("failed to set interface to: "+name+":", err)
	}
	if err := handle.SetupDataLink(); err != nil {
		t.Error("failed to setup data link:", err)
	}
	if err := handle.BecomePromiscuous(); err != nil {
		t.Fatal("failed to become promiscuous:", err)
	}
	if err := handle.SetImmediate(true); err != nil {
		t.Fatal("failed to enter immediate mode:", err)
	}

	// NOTE: if no wireless access points are around, packets will never be received.
	// To deal with this, we set a timeout after which we let the test pass automatically.
	notClosed := make(chan bool, 1)
	notClosed <- true
	close(notClosed)
	go func() {
		time.Sleep(time.Second * 5)
		if <-notClosed {
			handle.Close()
			t.Log("no packets received before timeout")
		}
	}()

	_, err = handle.ReceiveMany()
	if (<-notClosed) && err != nil {
		t.Error("failed to read packets:", err)
	}
}

func TestSend(t *testing.T) {
	name, ok := defaultOSXInterfaceName()
	if !ok {
		t.Fatal("no default interface")
	}
	handle, err := newBpfHandle()
	if err != nil {
		t.Fatal("could not open handle:", err)
	}
	defer handle.Close()
	if err := handle.SetInterface(name); err != nil {
		t.Fatal("failed to set interface to: "+name+":", err)
	}
	if err := handle.SetupDataLink(); err != nil {
		t.Error("failed to setup data link:", err)
	}
	if err := handle.BecomePromiscuous(); err != nil {
		t.Fatal("failed to become promiscuous:", err)
	}
	if err := handle.SetImmediate(true); err != nil {
		t.Fatal("failed to enter immediate mode:", err)
	}
	if err := handle.SetHeaderComplete(true); err != nil {
		t.Fatal("failed to enable header complete mode:", err)
	}

	// NOTE: this is a broadcast packet for a network called "PickleTown" on channel 11.
	frame := Frame("\x80\x00\x00\x00\xff\xff\xff\xff\xff\xff\x2e\xb0\x5d\x27\x56\xa9\x2e\xb0\x5d\x27\x56\xa9\x20\x77\xbb\x6a\x04\xd3\xe0\x00\x00\x00\xc8\x00\x11\x00\x00\x0a\x50\x69\x63\x6b\x6c\x65\x54\x6f\x77\x6e\x01\x08\x82\x84\x8b\x96\x24\x30\x48\x6c\x03\x01\x0b\x05\x04\x00\x02\x00\x00\x2a\x01\x00\x2f\x01\x00\x30\x14\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x00\x00\x32\x04\x0c\x12\x18\x60\x2d\x1a\xfc\x18\x1b\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x3d\x16\x0b\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xdd\x09\x00\x10\x18\x02\x00\xf0\x28\x00\x00\x05\x04\xde\x32")

	if err := handle.Send(frame); err != nil {
		t.Fatal("could not send packet:", err)
	}
}

func TestReadTimeout(t *testing.T) {
	name, ok := defaultOSXInterfaceName()
	if !ok {
		t.Fatal("no default interface")
	}
	handle, err := newBpfHandle()
	if err != nil {
		t.Fatal("could not open handle:", err)
	}
	defer handle.Close()
	if err := handle.SetReadBufferSize(0x1000); err != nil {
		t.Fatal("failed to set read buffer size:", err)
	}
	if err := handle.SetInterface(name); err != nil {
		t.Fatal("failed to set interface to: "+name+":", err)
	}
	if err := handle.SetupDataLink(); err != nil {
		t.Error("failed to setup data link:", err)
	}
	if err := handle.BecomePromiscuous(); err != nil {
		t.Fatal("failed to become promiscuous:", err)
	}
	if err := handle.SetHeaderComplete(true); err != nil {
		t.Fatal("failed to enable header complete mode:", err)
	}
	if err := handle.SetReadTimeout(time.Millisecond); err != nil {
		t.Fatal("failed to set read timeout:", err)
	}

	doneChan := make(chan error)
	timeoutChan := time.After(time.Second * 2)
	go func() {
		// If we keep reading really fast, eventually we should hit a 1ms timeout
		// unless there is REALLY high traffic on the channel.
		for {
			select {
			case <-timeoutChan:
				close(doneChan)
				return
			default:
			}
			if _, err := handle.ReceiveMany(); err != nil {
				doneChan <- err
				return
			}
		}
	}()

	endError := <-doneChan
	if endError == nil {
		t.Fatal("test timed out")
	} else if endError != errBPFReadTimeout {
		t.Fatal("unexpected error:", endError)
	}
}
