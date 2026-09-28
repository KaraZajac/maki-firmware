# usbd-serial, as maki uses it

betrusted-io's fork of usbd-serial 0.1.1 (branch `v0.1.1-betrusted`, commit `c20edaf`), vendored
for one change in `src/serial_port.rs`: every packet the serial port sends is short (511 bytes
at most on the badge's 512-byte endpoints), so no transfer ever needs a zero-length packet to
end it.

Why: the bao1x USB driver sends a zero-length packet by queueing a transfer descriptor of length
0 (`bulk_xfer` in `libs/bao1x-hal/src/usb/driver.rs`), which nobody has checked on the hardware.
While tracking down replies that reached the host with packets repeated (the actual cause was
the driver switching interrupts back on in the middle of a write; see its `write`), this was a
suspect worth taking out of play. It costs one byte in 512.
