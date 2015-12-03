// +build darwin
package gofi

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework CoreWLAN -framework Foundation
#import <CoreWLAN/CoreWLAN.h>
#include <stddef.h>

void * createInterface(char * name) {
	NSAutoreleasePool * pool = [[NSAutoreleasePool alloc] init];
	NSString * nameStr = [NSString stringWithUTF8String:name];
	free(name);
	void * res = (void *)[[[CWWiFiClient sharedWiFiClient] interfaceWithName:nameStr] retain];
	[pool release];
	return res;
}

void freeInterface(void * iface) {
	NSAutoreleasePool * pool = [[NSAutoreleasePool alloc] init];
	[(CWInterface *)iface release];
	[pool release];
}

bool setChannel(void * iface, int number) {
	NSAutoreleasePool * pool = [[NSAutoreleasePool alloc] init];
	CWInterface * interface = (CWInterface *)iface;
	NSSet * channels = [interface supportedWLANChannels];
	BOOL success = false;
	for (CWChannel * channel in channels) {
		if ([channel channelNumber] == (NSInteger)number) {
			success = [interface setWLANChannel:channel error:nil];
			break;
		}
	}
	[pool release];
	return success;
}

int getChannel(void * iface) {
	NSAutoreleasePool * pool = [[NSAutoreleasePool alloc] init];
	int res = (int)[(CWInterface *)iface wlanChannel].channelNumber;
	[pool release];
	return res;
}

void disassociate(void * iface) {
	NSAutoreleasePool * pool = [[NSAutoreleasePool alloc] init];
	[(CWInterface *)iface disassociate];
	[pool release];
}
*/
import "C"

import (
	"errors"
	"runtime"
	"strconv"
	"unsafe"
)

// An osxInterface makes it possible to interact with CoreWLAN on OS X.
type osxInterface struct {
	ptr unsafe.Pointer
}

// NewOSXInterface creates an interface given a name.
// This fails if the interface cannot be found or is not a WiFi device.
func NewOSXInterface(name string) (*osxInterface, error) {
	ptr := C.createInterface(C.CString(name))
	if ptr == nil {
		return nil, errors.New("interface could not be opened: " + name)
	}
	res := &osxInterface{ptr}
	runtime.SetFinalizer(res, res.free)
	return res, nil
}

// Channel returns the interface's current channel number.
func (i *osxInterface) Channel() int {
	return int(C.getChannel(i.ptr))
}

// SetChannel switches to a channel given its number.
func (i *osxInterface) SetChannel(channelNumber int) error {
	if bool(C.setChannel(i.ptr, C.int(channelNumber))) {
		return nil
	} else {
		return errors.New("could not switch to channel: " + strconv.Itoa(channelNumber))
	}
}

// Disassociate disconnects the interface from the current network.
// On El Capitan, it is usually necessary to disassociate before
// entering promiscuous mode.
func (i *osxInterface) Disassociate() {
	C.disassociate(i.ptr)
}

func (i *osxInterface) free() {
	C.freeInterface(i.ptr)
}
