//! How maki-link asks the vault for a login or a code on the browser's behalf.
//!
//! The vault finds what's saved for the site, asks the owner on screen (through the launcher),
//! and answers. The server takes exactly one connection, and maki-link makes it at boot, so no
//! app can ask the vault for secrets this way.

pub use maki_proto::device::Approval;
use num_traits::ToPrimitive;
use xous_ipc::Buffer;

pub const SERVER_NAME_VAULT_LINK: &str = "_maki vault link_";

/// How long the owner has to answer on screen. The desktop app gives up after 90 s, which leaves
/// room for one ask waiting behind another.
pub const ASK_TIMEOUT_S: u32 = 30;

#[derive(Debug, num_derive::FromPrimitive, num_derive::ToPrimitive)]
pub enum VaultLinkOp {
    /// Memory message (mutable lend) carrying a `Request`, answered in place.
    Request = 0,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Login = 0,
    Totp = 1,
    SaveLogin = 2,
}

/// A request, answered in place.
#[derive(Debug, Clone, Default, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct Request {
    /// a `Kind`
    pub kind: u8,
    pub site: String,
    /// The login to keep (SaveLogin), or the one found (Login, on the way back).
    pub username: String,
    pub password: String,
    /// On the way back: an `Approval`.
    pub approval: u8,
    /// On the way back, for Totp.
    pub code: String,
    pub valid_for_s: u8,
    /// Login: the password even if the vault holds a passkey for the site, which it otherwise
    /// answers `Passkey` instead of asking.
    pub even_with_passkey: bool,
}

impl Request {
    pub fn kind(&self) -> Option<Kind> {
        match self.kind {
            0 => Some(Kind::Login),
            1 => Some(Kind::Totp),
            2 => Some(Kind::SaveLogin),
            _ => None,
        }
    }
}

pub struct VaultLink {
    conn: xous::CID,
}

impl VaultLink {
    /// Blocks until the vault is serving.
    pub fn new(xns: &xous_names::XousNames) -> Result<Self, xous::Error> {
        Ok(VaultLink { conn: xns.request_connection_blocking(SERVER_NAME_VAULT_LINK)? })
    }

    fn call(&self, request: Request) -> Result<Request, xous::Error> {
        let mut buf = Buffer::into_buf(request).or(Err(xous::Error::InternalError))?;
        buf.lend_mut(self.conn, VaultLinkOp::Request.to_u32().unwrap())?;
        buf.to_original::<Request, _>().or(Err(xous::Error::InternalError))
    }

    fn approval(code: u8) -> Approval { Approval::from_u8(code).unwrap_or(Approval::Unavailable) }

    /// The login saved for `site`, if the owner allows it: (approval, username, password). A
    /// site maki holds a passkey for is answered `Passkey` unless `even_with_passkey`.
    pub fn login(&self, site: &str, even_with_passkey: bool) -> (Approval, String, String) {
        let request =
            Request { kind: Kind::Login as u8, site: site.into(), even_with_passkey, ..Default::default() };
        match self.call(request) {
            Ok(r) => (Self::approval(r.approval), r.username, r.password),
            Err(_) => (Approval::Unavailable, String::new(), String::new()),
        }
    }

    /// A code for `site`, if the owner allows it: (approval, code, seconds it stays valid).
    pub fn totp(&self, site: &str) -> (Approval, String, u8) {
        let request = Request { kind: Kind::Totp as u8, site: site.into(), ..Default::default() };
        match self.call(request) {
            Ok(r) => (Self::approval(r.approval), r.code, r.valid_for_s),
            Err(_) => (Approval::Unavailable, String::new(), 0),
        }
    }

    /// Keep a login for `site`, if the owner allows it.
    pub fn save_login(&self, site: &str, username: &str, password: &str) -> Approval {
        let request = Request {
            kind: Kind::SaveLogin as u8,
            site: site.into(),
            username: username.into(),
            password: password.into(),
            ..Default::default()
        };
        match self.call(request) {
            Ok(r) => Self::approval(r.approval),
            Err(_) => Approval::Unavailable,
        }
    }
}
