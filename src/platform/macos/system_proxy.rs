//! macOS proxy/DNS changes belong to the installed helper's recoverable lease.
//! The GUI never writes SystemConfiguration preferences itself.
use crate::Result;
pub fn recover_stale() -> Result<()> {
    Ok(())
}
pub fn guard(_: u16) -> Result<bool> {
    Err("Системным прокси macOS управляет помощник Eivro.".into())
}
