package gofi

import "testing"

func TestSetInterface(t *testing.T) {
	name, ok := defaultOSXInterfaceName()
	if !ok {
		t.Fatal("no default interface")
	}
	handle, err := newBpfHandle()
	if err != nil {
		t.Fatal("could not open handle:", err)
	}
	if err := handle.SetInterface(name); err != nil {
		t.Error("failed to set interface to: " + name + ":", err)
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
	if err := handle.SetInterface(name); err != nil {
		t.Fatal("failed to set interface to: " + name + ":", err)
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
	if err := handle.SetInterface(name); err != nil {
		t.Fatal("failed to set interface to: " + name + ":", err)
	}
	if err := handle.BecomePromiscuous(); err != nil {
		t.Error("failed to setup data link:", err)
	}
}
