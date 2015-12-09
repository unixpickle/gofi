// +build darwin

package gofi

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework CoreWLAN -framework Foundation
#import <CoreWLAN/CoreWLAN.h>
#include <stddef.h>

char * defaultInterface() {
	NSAutoreleasePool * pool = [[NSAutoreleasePool alloc] init];
	CWInterface * iface = [[CWWiFiClient sharedWiFiClient] interface];
	if (!iface) {
		[pool release];
		return NULL;
	}
	const char * name = [[iface interfaceName] UTF8String];
	char * res = malloc(strlen(name) + 1);
	strcpy(res, name);
	[pool release];
	return res;
}

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

bool setChannel(void * iface, int number, int width) {
	NSAutoreleasePool * pool = [[NSAutoreleasePool alloc] init];
	CWInterface * interface = (CWInterface *)iface;
	NSSet * channels = [interface supportedWLANChannels];
	BOOL success = false;
	for (CWChannel * channel in channels) {
		if ([channel channelNumber] != (NSInteger)number) {
			continue;
		}
		if (width == 20 && [channel channelWidth] != kCWChannelWidth20MHz) {
			continue;
		} else if (width == 40 && [channel channelWidth] != kCWChannelWidth40MHz) {
			continue;
		}
		success = [interface setWLANChannel:channel error:nil];
		break;
	}
	[pool release];
	return success;
}

void getChannel(void * iface, int * number, int * width) {
	NSAutoreleasePool * pool = [[NSAutoreleasePool alloc] init];
	CWChannel * ch = [(CWInterface *)iface wlanChannel];
	*number = (int)ch.channelNumber;
	if (ch.channelWidth == kCWChannelWidth20MHz) {
		*width = 20;
	} else if (ch.channelWidth == kCWChannelWidth40MHz) {
		*width = 40;
	}
	[pool release];
}

int supportedChannelCount(void * iface) {
	NSAutoreleasePool * pool = [[NSAutoreleasePool alloc] init];
	int res = [[(CWInterface *)iface supportedWLANChannels] count];
	[pool release];
	return res;
}

void supportedChannels(void * iface, int * numbers, int * widths, int maxLen) {
	NSAutoreleasePool * pool = [[NSAutoreleasePool alloc] init];
	NSSet * s = [(CWInterface *)iface supportedWLANChannels];
	int i = 0;
	for (CWChannel * ch in s) {
		if (i == maxLen) {
			break;
		}
		if (ch.channelWidth == kCWChannelWidth20MHz) {
			widths[i] = 20;
		} else if (ch.channelWidth == kCWChannelWidth40MHz) {
			widths[i] = 40;
		}
		numbers[i++] = (int)ch.channelNumber;
	}
	[pool release];
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
	"unsafe"
)

// An osxInterface makes it possible to interact with CoreWLAN on OS X.
type osxInterface struct {
	ptr unsafe.Pointer
}

// defaultOSXInterfaceName returns the name of the default interface.
// If no interface exists, the ok value is set to false.
func defaultOSXInterfaceName() (name string, ok bool) {
	ptr := C.defaultInterface()
	if ptr == nil {
		return "", false
	}
	s := C.GoString(ptr)
	C.free(unsafe.Pointer(ptr))
	return s, true
}

// newOSXInterface creates an interface given a name.
// This fails if the interface cannot be found or is not a WiFi device.
func newOSXInterface(name string) (*osxInterface, error) {
	ptr := C.createInterface(C.CString(name))
	if ptr == nil {
		return nil, errors.New("interface could not be opened: " + name)
	}
	res := &osxInterface{ptr}
	runtime.SetFinalizer(res, func(i *osxInterface) {
		i.free()
	})
	return res, nil
}

// SupportedChannels generates an list of supported channels in
// an unspecified order.
func (i *osxInterface) SupportedChannels() []Channel {
	count := C.supportedChannelCount(i.ptr)
	numbers := make([]C.int, int(count))
	widths := make([]C.int, int(count))
	C.supportedChannels(i.ptr, (*C.int)(&numbers[0]), (*C.int)(&widths[0]), count)

	res := make([]Channel, int(count))
	for i := range res {
		res[i] = Channel{
			Number: int(numbers[i]),
			Width:  NewChannelWidthMegahertz(int(widths[i])),
		}
	}

	return res
}

// Channel returns the interface's current channel number.
func (i *osxInterface) Channel() Channel {
	var number, width C.int
	C.getChannel(i.ptr, &number, &width)
	return Channel{
		Number: int(number),
		Width:  NewChannelWidthMegahertz(int(width)),
	}
}

// SetChannel switches to a channel.
func (i *osxInterface) SetChannel(c Channel) error {
	res := C.setChannel(i.ptr, C.int(c.Number), C.int(c.Width.Megahertz()))
	if bool(res) {
		return nil
	} else {
		return errors.New("could not switch to channel")
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
