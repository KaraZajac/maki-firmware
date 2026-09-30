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

## Also fixed in maki's copy (2026-09-30)

Correctness and safety, not style; the crate's remaining clippy lints are cosmetic and left alone
to keep this copy close to upstream.

- `SerialPort::new` built its two 128-byte buffers with `mem::uninitialized()`, which is undefined
  behaviour for a `[u8; N]`. `DefaultBufferStore` now has a zeroed `Default`, used instead. (The
  badge's own USB service, `usb-bao1x`, never called `new`: it passes zeroed buffers to
  `new_with_store`. But the constructor was compiled in, and the lint flagged it.)
- `StopBits` and `ParityType` were made from the host's `SET_LINE_CODING` byte with
  `mem::transmute`, on enums with no `#[repr]`, so their layout wasn't guaranteed. Both are now a
  `match`, with the same values and the same fallbacks, and tests cover every byte.
- Two stray `&` in front of `copy_from_slice` calls (the copies happened; the `&` did nothing),
  an unused constant, and `CDC_COMM_PROTOCOL_AT` written `01` rather than `0x01`.
- The tests in `buffer.rs` were for upstream's older `generic_array` buffer and couldn't compile
  against this one. They're ported to the store-backed buffer, with two more (partial reads and
  writes, the zeroed store). The usage example in `lib.rs` is illustrative and now `ignore`d.
  `cargo test -p usbd-serial` passes.
