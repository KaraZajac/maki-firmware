//! maki's functions for a native app (`kind = "native"`): the same as the WebAssembly imports
//! (`sys` in lib.rs), carried over maki's app service (`maki_native::service`). The app's stub
//! connected it to the service before confining it: connecting again returns that connection,
//! and nothing else can be connected to. Drawing is recorded here and sent in one message when
//! the app presents.
//!
//! maki-app's functions are for the app's main thread: it keeps its frame in a static.

extern crate alloc;

use alloc::vec::Vec;
use core::cell::UnsafeCell;

use maki_native::draw::{Draw, Frame};
use maki_native::service;

struct Global {
    conn: UnsafeCell<Option<xous::CID>>,
    frame: UnsafeCell<Option<Frame>>,
}

// the app's main thread only (see above)
unsafe impl Sync for Global {}

static G: Global = Global { conn: UnsafeCell::new(None), frame: UnsafeCell::new(None) };

// maki's codes (`maki_wasm`'s, which `result` in lib.rs reads)
const INVALID: i32 = -3;
const FAILED: i32 = -5;

fn conn() -> xous::CID {
    let conn = unsafe { &mut *G.conn.get() };
    *conn.get_or_insert_with(|| {
        let sid = xous::SID::from_bytes(&service::SID).unwrap();
        xous::connect(sid).expect("maki's app service: a native app runs only on maki")
    })
}

fn frame() -> &'static mut Frame { unsafe { &mut *G.frame.get() }.get_or_insert_with(Frame::new) }

fn push(op: Draw) { frame().push(&op) }

/// A request in a lent buffer (`maki_native::service`): its status, what came back (as much
/// as there was room for) and its whole length.
fn exchange(op: usize, payload: &[u8], room: usize) -> (i32, Vec<u8>, usize) {
    let size = (service::HEAD + payload.len().max(room)).next_multiple_of(4096);
    let mut range = xous::map_memory(None, None, size, xous::MemoryFlags::R | xous::MemoryFlags::W)
        .expect("memory for a request to maki");
    {
        let buf = unsafe { range.as_slice_mut::<u8>() };
        buf[service::HEAD..service::HEAD + payload.len()].copy_from_slice(payload);
        service::set_head(buf, 0, payload.len());
    }
    let sent =
        xous::send_message(conn(), xous::Message::new_lend_mut(op, range, None, xous::MemorySize::new(size)));
    let (status, got, whole) = {
        let buf = unsafe { range.as_slice::<u8>() };
        let (status, len) = service::head(buf);
        (status, buf[service::HEAD..service::HEAD + len.min(size - service::HEAD)].to_vec(), len)
    };
    xous::unmap_memory(range).ok();
    if sent.is_err() {
        return (FAILED, Vec::new(), 0);
    }
    (status, got, whole)
}

fn request(op: usize, payload: &[u8], room: usize) -> (i32, Vec<u8>) {
    let (status, got, _) = exchange(op, payload, room);
    (status, got)
}

fn blocking(op: usize, arg: usize) -> Option<xous::Result> {
    xous::send_message(conn(), xous::Message::new_blocking_scalar(op, arg, 0, 0, 0)).ok()
}

unsafe fn slice<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if len == 0 { &[] } else { core::slice::from_raw_parts(ptr, len) }
}

unsafe fn slice_mut<'a>(ptr: *mut u8, len: usize) -> &'a mut [u8] {
    if len == 0 { &mut [] } else { core::slice::from_raw_parts_mut(ptr, len) }
}

unsafe fn str<'a>(ptr: *const u8, len: usize) -> &'a str {
    core::str::from_utf8(slice(ptr, len)).unwrap_or("")
}

/// Copies what came back into the app's buffer as far as it fits, and returns its whole
/// length, or the status if it isn't 0: what the WebAssembly imports return.
unsafe fn copy_out(status: i32, got: &[u8], whole: usize, ptr: *mut u8, cap: usize) -> i32 {
    if status != 0 {
        return status;
    }
    let n = got.len().min(cap);
    slice_mut(ptr, cap)[..n].copy_from_slice(&got[..n]);
    whole as i32
}

pub unsafe fn screen_width() -> i32 { crate::WIDTH }
pub unsafe fn screen_height() -> i32 { crate::HEIGHT }
pub unsafe fn clear(color: i32) { push(Draw::Clear { color: color as u8 }) }
pub unsafe fn pixel(x: i32, y: i32, color: i32) {
    push(Draw::Pixel { x: x as i16, y: y as i16, color: color as u8 })
}
pub unsafe fn line(x0: i32, y0: i32, x1: i32, y1: i32, color: i32) {
    push(Draw::Line { x0: x0 as i16, y0: y0 as i16, x1: x1 as i16, y1: y1 as i16, color: color as u8 })
}
pub unsafe fn rect(x: i32, y: i32, w: i32, h: i32, color: i32, filled: i32) {
    push(Draw::Rect {
        x: x as i16,
        y: y as i16,
        w: w as i16,
        h: h as i16,
        color: color as u8,
        filled: filled != 0,
    })
}
pub unsafe fn text(x: i32, y: i32, ptr: *const u8, len: usize, style: i32, color: i32) -> i32 {
    let s = str(ptr, len);
    push(Draw::Text { x: x as i16, y: y as i16, style: style as u8, color: color as u8, text: s });
    text_width(ptr, len, style)
}
pub unsafe fn text_width(ptr: *const u8, len: usize, style: i32) -> i32 {
    let mut payload = Vec::with_capacity(len + 1);
    payload.push(style as u8);
    payload.extend_from_slice(slice(ptr, len));
    match request(service::TEXT_WIDTH, &payload, 4) {
        (0, w) if w.len() >= 4 => i32::from_le_bytes([w[0], w[1], w[2], w[3]]),
        _ => 0,
    }
}
pub unsafe fn blit(x: i32, y: i32, w: i32, h: i32, ptr: *const u8, color: i32) {
    if w <= 0 || h <= 0 {
        return;
    }
    let rows = slice(ptr, ((w + 7) / 8 * h) as usize);
    push(Draw::Blit { x: x as i16, y: y as i16, w: w as i16, h: h as i16, color: color as u8, rows })
}
pub unsafe fn qr(x: i32, y: i32, ptr: *const u8, len: usize, size: i32) -> i32 {
    push(Draw::Qr { x: x as i16, y: y as i16, size: size as i16, data: slice(ptr, len) });
    size
}
pub unsafe fn present() {
    let f = frame();
    request(service::PRESENT, f.bytes(), 0);
    f.clear();
}
pub unsafe fn wait(timeout_ms: i32) -> i32 {
    let arg = if timeout_ms < 0 { u32::MAX as usize } else { timeout_ms as usize };
    match blocking(service::WAIT, arg) {
        Some(xous::Result::Scalar1(code)) if code != service::EXITED => code as u32 as i32,
        _ => abort_str("waited after being told to exit"),
    }
}
pub unsafe fn menu(ptr: *const u8, len: usize) -> i32 { request(service::MENU, slice(ptr, len), 0).0 }
pub unsafe fn storage_get(kptr: *const u8, klen: usize, vptr: *mut u8, vcap: usize) -> i32 {
    let (status, got, whole) = exchange(service::STORAGE_GET, slice(kptr, klen), vcap);
    copy_out(status, &got, whole, vptr, vcap)
}
pub unsafe fn storage_set(kptr: *const u8, klen: usize, vptr: *const u8, vlen: usize) -> i32 {
    if klen > 255 {
        return INVALID;
    }
    let mut payload = Vec::with_capacity(1 + klen + vlen);
    payload.push(klen as u8);
    payload.extend_from_slice(slice(kptr, klen));
    payload.extend_from_slice(slice(vptr, vlen));
    request(service::STORAGE_SET, &payload, 0).0
}
pub unsafe fn storage_delete(kptr: *const u8, klen: usize) -> i32 {
    request(service::STORAGE_DELETE, slice(kptr, klen), 0).0
}
pub unsafe fn storage_key(index: i32, ptr: *mut u8, cap: usize) -> i32 {
    let (status, got, whole) = exchange(service::STORAGE_KEY, &index.to_le_bytes(), cap);
    copy_out(status, &got, whole, ptr, cap)
}
pub unsafe fn millis() -> i64 {
    match blocking(service::MILLIS, 0) {
        Some(xous::Result::Scalar2(lo, hi)) => ((hi as u64) << 32 | lo as u32 as u64) as i64,
        _ => 0,
    }
}
fn time() -> (i64, i32) {
    match blocking(service::UNIX_TIME, 0) {
        Some(xous::Result::Scalar5(lo, hi, verified, known, _)) if known != 0 => {
            (((hi as u64) << 32 | lo as u32 as u64) as i64, verified as i32)
        }
        _ => (-1, 0),
    }
}
pub unsafe fn unix_time() -> i64 { time().0 }
pub unsafe fn time_verified() -> i32 { time().1 }
pub unsafe fn random(ptr: *mut u8, len: usize) {
    let (status, got) = request(service::RANDOM, &(len as u32).to_le_bytes(), len);
    if status != 0 || got.len() < len {
        abort_str("random: more than maki gives at once");
    }
    slice_mut(ptr, len).copy_from_slice(&got[..len]);
}
pub unsafe fn log(ptr: *const u8, len: usize) { request(service::LOG, slice(ptr, len), 0); }

fn abort_str(why: &str) -> ! {
    request(service::LOG, why.as_bytes(), 0);
    xous::send_message(conn(), xous::Message::new_scalar(service::EXIT, 1, 0, 0, 0)).ok();
    xous::terminate_process(1)
}
pub unsafe fn abort(ptr: *const u8, len: usize) -> ! { abort_str(str(ptr, len)) }

pub unsafe fn ask(ptr: *const u8, len: usize, timeout_s: i32) -> i32 {
    let mut payload = Vec::with_capacity(4 + len);
    payload.extend_from_slice(&timeout_s.to_le_bytes());
    payload.extend_from_slice(slice(ptr, len));
    request(service::ASK, &payload, 0).0
}
pub unsafe fn ask_review(ptr: *const u8, len: usize, timeout_s: i32) -> i32 {
    let mut payload = Vec::with_capacity(4 + len);
    payload.extend_from_slice(&timeout_s.to_le_bytes());
    payload.extend_from_slice(slice(ptr, len));
    request(service::ASK_REVIEW, &payload, 0).0
}
unsafe fn key(op: usize, lptr: *const u8, llen: usize, out: *mut u8) -> i32 {
    let (status, got) = request(op, slice(lptr, llen), 32);
    if status == 0 && got.len() == 32 {
        slice_mut(out, 32).copy_from_slice(&got);
    }
    status
}
pub unsafe fn key_secret(lptr: *const u8, llen: usize, out: *mut u8) -> i32 {
    key(service::KEY_SECRET, lptr, llen, out)
}
pub unsafe fn key_public(lptr: *const u8, llen: usize, out: *mut u8) -> i32 {
    key(service::KEY_PUBLIC, lptr, llen, out)
}
pub unsafe fn key_sign(lptr: *const u8, llen: usize, mptr: *const u8, mlen: usize, out: *mut u8) -> i32 {
    if llen > 255 {
        return INVALID;
    }
    let mut payload = Vec::with_capacity(1 + llen + mlen);
    payload.push(llen as u8);
    payload.extend_from_slice(slice(lptr, llen));
    payload.extend_from_slice(slice(mptr, mlen));
    let (status, got) = request(service::KEY_SIGN, &payload, 64);
    if status == 0 && got.len() == 64 {
        slice_mut(out, 64).copy_from_slice(&got);
    }
    status
}
pub unsafe fn key_schnorr_public(lptr: *const u8, llen: usize, out: *mut u8) -> i32 {
    key(service::KEY_SCHNORR_PUBLIC, lptr, llen, out)
}
pub unsafe fn key_schnorr_sign(lptr: *const u8, llen: usize, mptr: *const u8, out: *mut u8) -> i32 {
    if llen > 255 {
        return INVALID;
    }
    let mut payload = Vec::with_capacity(1 + llen + 32);
    payload.push(llen as u8);
    payload.extend_from_slice(slice(lptr, llen));
    payload.extend_from_slice(slice(mptr, 32));
    let (status, got) = request(service::KEY_SCHNORR_SIGN, &payload, 64);
    if status == 0 && got.len() == 64 {
        slice_mut(out, 64).copy_from_slice(&got);
    }
    status
}
pub unsafe fn key_x25519_public(lptr: *const u8, llen: usize, out: *mut u8) -> i32 {
    key(service::KEY_X25519_PUBLIC, lptr, llen, out)
}
pub unsafe fn key_x25519_agree(lptr: *const u8, llen: usize, pptr: *const u8, out: *mut u8) -> i32 {
    if llen > 255 {
        return INVALID;
    }
    let mut payload = Vec::with_capacity(1 + llen + 32);
    payload.push(llen as u8);
    payload.extend_from_slice(slice(lptr, llen));
    payload.extend_from_slice(slice(pptr, 32));
    let (status, got) = request(service::KEY_X25519_AGREE, &payload, 32);
    if status == 0 && got.len() == 32 {
        slice_mut(out, 32).copy_from_slice(&got);
    }
    status
}
pub unsafe fn type_text(ptr: *const u8, len: usize) -> i32 {
    request(service::TYPE_TEXT, slice(ptr, len), 0).0
}
pub unsafe fn link_read(ptr: *mut u8, cap: usize) -> i32 {
    let (status, got, whole) = exchange(service::LINK_READ, &[], cap.max(4096));
    copy_out(status, &got, whole, ptr, cap)
}
pub unsafe fn link_reply(ptr: *const u8, len: usize) -> i32 {
    request(service::LINK_REPLY, slice(ptr, len), 0).0
}
pub unsafe fn camera_scan_qr(ptr: *mut u8, cap: usize) -> i32 {
    let (status, got, whole) = exchange(service::SCAN_QR, &[], cap.max(1024));
    copy_out(status, &got, whole, ptr, cap)
}
pub unsafe fn motion_read(ptr: *mut u8) -> i32 {
    match blocking(service::MOTION, 0) {
        Some(xous::Result::Scalar5(status, x, y, z, _)) if status == 0 => {
            let out = slice_mut(ptr, 6);
            for (i, v) in [x, y, z].iter().enumerate() {
                out[i * 2..i * 2 + 2].copy_from_slice(&(*v as u32 as i32 as i16).to_le_bytes());
            }
            0
        }
        Some(xous::Result::Scalar5(status, ..)) => status as u32 as i32,
        _ => FAILED,
    }
}

pub unsafe fn key_press(code: i32, shift: i32) -> i32 {
    let arg = (code as u8 as usize) | if shift != 0 { 0x100 } else { 0 };
    match blocking(service::KEY_PRESS, arg) {
        Some(xous::Result::Scalar1(status)) => status as u32 as i32,
        _ => FAILED,
    }
}
pub unsafe fn screen_dark(dark: i32) { blocking(service::SCREEN_DARK, (dark != 0) as usize); }
pub unsafe fn motion_range(g: i32) -> i32 {
    match blocking(service::MOTION_RANGE, g.clamp(0, 16) as usize) {
        Some(xous::Result::Scalar1(got)) => got as u32 as i32,
        _ => FAILED,
    }
}

/// The app returned: maki ends its process. (Called by the program `maki build` wraps a native
/// app in, which links it as a library.)
#[doc(hidden)]
#[no_mangle]
pub extern "C" fn maki_native_finished() {
    xous::send_message(conn(), xous::Message::new_scalar(service::EXIT, 0, 0, 0, 0)).ok();
}

/// It panicked: why, for maki's "stopped" screen, and its process ends.
#[doc(hidden)]
#[no_mangle]
pub unsafe extern "C" fn maki_native_crashed(ptr: *const u8, len: usize) -> ! { abort_str(str(ptr, len)) }

#[cfg(feature = "wallet")]
mod wallet_calls {
    use super::*;

    /// A derivation path as the app service takes it: little-endian u32s, at most eight.
    unsafe fn path_bytes(pptr: *const u32, plen: usize) -> Option<Vec<u8>> {
        if plen > 8 {
            return None;
        }
        let path = if plen == 0 { &[][..] } else { core::slice::from_raw_parts(pptr, plen) };
        Some(path.iter().flat_map(|i| i.to_le_bytes()).collect())
    }

    /// What came back, if it fits the app's buffer: its length, or the status, or `TOO_BIG`.
    unsafe fn fits(status: i32, got: &[u8], out: *mut u8, cap: usize) -> i32 {
        if status != 0 {
            return status;
        }
        if got.len() > cap {
            return -4;
        }
        slice_mut(out, got.len()).copy_from_slice(got);
        got.len() as i32
    }

    pub unsafe fn wallet_fingerprint(out: *mut u8) -> i32 {
        let (status, got) = request(service::WALLET_FINGERPRINT, &[], 4);
        if status == 0 && got.len() == 4 {
            slice_mut(out, 4).copy_from_slice(&got);
        }
        status
    }

    pub unsafe fn wallet_public(pptr: *const u32, plen: usize, form: i32, out: *mut u8, cap: usize) -> i32 {
        let (Some(path), Ok(form)) = (path_bytes(pptr, plen), u8::try_from(form)) else { return INVALID };
        let mut payload = Vec::with_capacity(1 + path.len());
        payload.push(form);
        payload.extend_from_slice(&path);
        let (status, got) = request(service::WALLET_PUBLIC, &payload, 69);
        fits(status, &got, out, cap)
    }

    pub unsafe fn wallet_review(tptr: *const u8, tlen: usize, signatures: i32, timeout_s: i32) -> i32 {
        let mut payload = Vec::with_capacity(8 + tlen);
        payload.extend_from_slice(&(signatures as u32).to_le_bytes());
        payload.extend_from_slice(&timeout_s.to_le_bytes());
        payload.extend_from_slice(slice(tptr, tlen));
        request(service::WALLET_REVIEW, &payload, 0).0
    }

    pub unsafe fn wallet_sign(
        pptr: *const u32,
        plen: usize,
        dptr: *const u8,
        scheme: i32,
        out: *mut u8,
        cap: usize,
    ) -> i32 {
        let (Some(path), Ok(scheme)) = (path_bytes(pptr, plen), u8::try_from(scheme)) else { return INVALID };
        let mut payload = Vec::with_capacity(33 + path.len());
        payload.push(scheme);
        payload.extend_from_slice(slice(dptr, 32));
        payload.extend_from_slice(&path);
        let (status, got) = request(service::WALLET_SIGN, &payload, 65);
        fits(status, &got, out, cap)
    }

    pub unsafe fn wallet_subaddress(
        pptr: *const u32,
        plen: usize,
        major: i32,
        minor: i32,
        out: *mut u8,
    ) -> i32 {
        let Some(path) = path_bytes(pptr, plen) else { return INVALID };
        let mut payload = Vec::with_capacity(8 + path.len());
        payload.extend_from_slice(&(major as u32).to_le_bytes());
        payload.extend_from_slice(&(minor as u32).to_le_bytes());
        payload.extend_from_slice(&path);
        let (status, got) = request(service::WALLET_SUBADDRESS, &payload, 64);
        match fits(status, &got, out, 64) {
            64 => 0,
            n if n < 0 => n,
            _ => -5,
        }
    }

    pub unsafe fn wallet_show_backup(pptr: *const u32, plen: usize) -> i32 {
        let Some(path) = path_bytes(pptr, plen) else { return INVALID };
        request(service::WALLET_SHOW_BACKUP, &path, 0).0
    }

    pub unsafe fn wallet_type_password(pptr: *const u32, plen: usize) -> i32 {
        let Some(path) = path_bytes(pptr, plen) else { return INVALID };
        request(service::WALLET_TYPE_PASSWORD, &path, 0).0
    }

    pub unsafe fn wallet_show_password(pptr: *const u32, plen: usize, lptr: *const u8, llen: usize) -> i32 {
        let Some(path) = path_bytes(pptr, plen) else { return INVALID };
        // the label's length in a byte: longer than maki takes is refused before it's sent
        if llen > 255 {
            return -4;
        }
        let mut payload = Vec::with_capacity(1 + llen + path.len());
        payload.push(llen as u8);
        payload.extend_from_slice(slice(lptr, llen));
        payload.extend_from_slice(&path);
        request(service::WALLET_SHOW_PASSWORD, &payload, 0).0
    }

    pub unsafe fn wallet_monero_view_key(pptr: *const u32, plen: usize, out: *mut u8) -> i32 {
        let Some(path) = path_bytes(pptr, plen) else { return INVALID };
        let (status, got) = request(service::WALLET_MONERO_VIEW_KEY, &path, 32);
        match fits(status, &got, out, 32) {
            32 => 0,
            n if n < 0 => n,
            _ => -5,
        }
    }

    pub unsafe fn wallet_monero_key_image(
        pptr: *const u32,
        plen: usize,
        optr: *const u8,
        out: *mut u8,
    ) -> i32 {
        let Some(path) = path_bytes(pptr, plen) else { return INVALID };
        let mut payload = Vec::with_capacity(80 + path.len());
        payload.extend_from_slice(slice(optr, 80));
        payload.extend_from_slice(&path);
        let (status, got) = request(service::WALLET_MONERO_KEY_IMAGE, &payload, 96);
        match fits(status, &got, out, 96) {
            96 => 0,
            n if n < 0 => n,
            _ => -5,
        }
    }

    pub unsafe fn wallet_monero_sign(
        pptr: *const u32,
        plen: usize,
        rptr: *const u8,
        rlen: usize,
        out: *mut u8,
        cap: usize,
    ) -> i32 {
        let Some(path) = path_bytes(pptr, plen) else { return INVALID };
        let mut payload = Vec::with_capacity(4 + rlen + path.len());
        payload.extend_from_slice(&(rlen as u32).to_le_bytes());
        payload.extend_from_slice(slice(rptr, rlen));
        payload.extend_from_slice(&path);
        let (status, got) = request(service::WALLET_MONERO_SIGN, &payload, cap);
        fits(status, &got, out, cap)
    }

    pub unsafe fn wallet_sign_ed25519(
        pptr: *const u32,
        plen: usize,
        mptr: *const u8,
        mlen: usize,
        out: *mut u8,
    ) -> i32 {
        let Some(path) = path_bytes(pptr, plen) else { return INVALID };
        let mut payload = Vec::with_capacity(4 + mlen + path.len());
        payload.extend_from_slice(&(mlen as u32).to_le_bytes());
        payload.extend_from_slice(slice(mptr, mlen));
        payload.extend_from_slice(&path);
        let (status, got) = request(service::WALLET_SIGN_ED25519, &payload, 64);
        match fits(status, &got, out, 64) {
            64 => 0,
            n if n < 0 => n,
            _ => -5,
        }
    }

    pub unsafe fn wallet_sign_cardano(
        pptr: *const u32,
        plen: usize,
        mptr: *const u8,
        mlen: usize,
        out: *mut u8,
    ) -> i32 {
        let Some(path) = path_bytes(pptr, plen) else { return INVALID };
        let mut payload = Vec::with_capacity(4 + mlen + path.len());
        payload.extend_from_slice(&(mlen as u32).to_le_bytes());
        payload.extend_from_slice(slice(mptr, mlen));
        payload.extend_from_slice(&path);
        let (status, got) = request(service::WALLET_SIGN_CARDANO, &payload, 64);
        match fits(status, &got, out, 64) {
            64 => 0,
            n if n < 0 => n,
            _ => -5,
        }
    }
}
#[cfg(feature = "wallet")]
pub use wallet_calls::*;
