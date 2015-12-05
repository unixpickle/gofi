# gofi

**gofi** provides a super simple API for sending and receiving data-link packets over WiFi.

# Supported Platforms

Right now, gofi is only supported on OS X. This will surely change soon, as I plan to write an implementation for Linux.

# Usage

**NOTE:** you can find [full documentation on Godoc](http://godoc.org/github.com/unixpickle/gofi).

To start transferring data over a WiFi device, you must create a `Handle`. For example:

    handle, err := gofi.NewHandle("en1")

If you do not know the interface name for your WiFi device ahead of time, gofi gives you an easy way to figure it out:

	name, err := gofi.DefaultInterfaceName()
	if err != nil {
        // The system has no default WiFi defice!!!
        panic("do something here")
	}
	handle, err := gofi.NewHandle(name)

Since WiFi communications can take place on any number of channels, you will most likely want to hop channels immediately. You can do this using the `SetChannel` function:

    handle.SetChannel(11)

Once you're tuned into a channel, you can receive packets using the `Receive` function. For example:

	for {
		frame, radio, err := handle.Receive()
		if err != nil {
            // Could not ready any more data! Maybe the device was unplugged.
			break
		}
		sourceMACAddress := frame[4:10]
		fmt.Println("got", len(frame), "bytes on frequency", radio.Frequency,
            "MHz", "from MAC", sourceMACAddress)
	}

Sending packets is simple as well, but crafting the packets is up to you!

	frame := Frame("\x80\x00\x00...")
    if err := handle.Send(frame); err != nil {
        // Could not send the packet! Did you remember to compute the trailing checksum?
    }
