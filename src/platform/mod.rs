//! OS boundaries shared by the UI and connection controller.
#[cfg(target_os = "macos")]
pub mod macos;

pub const KILL_SWITCH_SUPPORTED: bool = cfg!(target_os = "linux");
#[cfg(target_os = "linux")]
pub const TUN_NAME: &str = "eivro0";
#[cfg(target_os = "macos")]
pub const TUN_NAME: &str = "utun233";
#[cfg(target_os = "linux")]
pub const TUN_DNS_MODE: &str = "hijack";
#[cfg(target_os = "macos")]
pub const TUN_DNS_MODE: &str = "disabled";
#[cfg(target_os = "linux")]
pub const INSTALLED_CORE: &str = "/usr/libexec/eivro/sing-box";
#[cfg(target_os = "macos")]
pub const INSTALLED_CORE: &str = "/Library/PrivilegedHelperTools/io.eivro/sing-box";
#[cfg(target_os = "linux")]
pub const INSTALLED_XRAY: &str = "/usr/libexec/eivro/xray";
#[cfg(target_os = "macos")]
pub const INSTALLED_XRAY: &str = "/Library/PrivilegedHelperTools/io.eivro/xray";
#[cfg(target_os = "linux")]
pub const HELPER: &str = "/usr/libexec/eivro/eivro-tun";
#[cfg(target_os = "macos")]
pub const HELPER: &str = "/Library/PrivilegedHelperTools/io.eivro/eivro-tun";
#[cfg(target_os = "linux")]
pub const HELPER_HINT: &str = "Для TUN установите RPM/DEB этой версии Eivro.";
#[cfg(target_os = "macos")]
pub const HELPER_HINT: &str = "Установите пакет Eivro.pkg этой версии: нужен системный помощник.";
#[cfg(target_os = "linux")]
pub const PROXY_HINT: &str = "Системный прокси GNOME";
#[cfg(target_os = "macos")]
pub const PROXY_HINT: &str = "Системный прокси macOS";

#[cfg(any(target_os = "macos", test))]
pub mod wire;
