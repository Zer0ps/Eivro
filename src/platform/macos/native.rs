//! Small, owned FFI boundary. Native code returns allocated UTF-8 JSON only;
//! traffic, credentials and subscription contents are never logged.
use crate::Result;
use std::ffi::{CStr, CString, c_char, c_void};
unsafe extern "C" {
    pub fn eivro_desktop_start(
        callback: extern "C" fn(*mut c_void, i32, bool),
        context: *mut c_void,
    ) -> *mut c_void;
    pub fn eivro_desktop_update(handle: *mut c_void, running: bool, wanted: bool);
    pub fn eivro_desktop_stop(handle: *mut c_void);
    fn eivro_interfaces() -> *mut c_char;
    fn eivro_uplink() -> *mut c_char;
    fn eivro_applications() -> *mut c_char;
    fn eivro_settings_plan(port: u16, tun: bool) -> *mut c_char;
    fn eivro_settings_apply(plan: *const c_char, restore: bool) -> bool;
    fn eivro_authorize(token: *mut u8) -> *const c_void;
    fn eivro_verify_authorization(token: *const u8) -> bool;
    fn eivro_authorization_free(handle: *const c_void);
}
fn take_json<T: serde::de::DeserializeOwned>(raw: *mut c_char) -> Result<T> {
    if raw.is_null() {
        return Err("Системные настройки macOS недоступны.".into());
    }
    let result = unsafe { serde_json::from_slice(CStr::from_ptr(raw).to_bytes()) };
    unsafe {
        libc::free(raw.cast());
    }
    result.map_err(|_| "Некорректный ответ macOS.".into())
}
pub fn interfaces() -> Result<serde_json::Value> {
    take_json(unsafe { eivro_interfaces() })
}
pub fn uplink() -> Result<String> {
    take_json(unsafe { eivro_uplink() })
}
pub fn applications() -> Vec<(String, String)> {
    take_json(unsafe { eivro_applications() }).unwrap_or_default()
}
pub fn settings_plan(port: u16, tun: bool) -> Result<String> {
    let value: serde_json::Value = take_json(unsafe { eivro_settings_plan(port, tun) })?;
    serde_json::to_string(&value).map_err(|_| "Не удалось подготовить настройки macOS.".into())
}
pub fn settings_apply(plan: &str, restore: bool) -> Result<()> {
    let plan = CString::new(plan).map_err(|_| "Неверный снимок настроек.".to_string())?;
    if unsafe { eivro_settings_apply(plan.as_ptr(), restore) } {
        Ok(())
    } else {
        Err("Не удалось применить или восстановить сетевые настройки macOS.".into())
    }
}
pub struct Authorization {
    handle: usize,
    token: [u8; 32],
}
impl Authorization {
    pub fn acquire() -> Result<Self> {
        let mut token = [0; 32];
        let handle = unsafe { eivro_authorize(token.as_mut_ptr()) };
        if handle.is_null() {
            return Err("Доступ TUN отменён или права macOS не предоставлены.".into());
        }
        Ok(Self {
            handle: handle as usize,
            token,
        })
    }
    pub fn token(&self) -> [u8; 32] {
        self.token
    }
}
impl Drop for Authorization {
    fn drop(&mut self) {
        unsafe {
            eivro_authorization_free(self.handle as *const c_void);
        }
        self.token.fill(0);
    }
}
pub fn verify_authorization(token: &[u8; 32]) -> bool {
    unsafe { eivro_verify_authorization(token.as_ptr()) }
}
