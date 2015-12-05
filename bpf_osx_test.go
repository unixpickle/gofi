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
