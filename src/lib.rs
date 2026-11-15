pub mod catalog;
pub mod config;
pub mod connectivity;
#[cfg(feature = "gui")]
#[cfg_attr(target_os = "macos", path = "platform/macos/desktop.rs")]
#[cfg_attr(windows, path = "platform/windows/desktop.rs")]
pub mod desktop;
pub mod diagnostics;
#[cfg(target_os = "linux")]
pub mod domain_dns;
#[cfg(target_os = "linux")]
pub mod guard;
pub mod import;
pub mod network;
pub mod platform;
pub mod policy;
pub mod presets;
#[cfg_attr(windows, path = "platform/windows/privacy.rs")]
pub mod privacy;
#[cfg_attr(windows, path = "platform/windows/process.rs")]
pub mod process;
pub mod recovery;
#[cfg_attr(windows, path = "platform/windows/resolver.rs")]
pub mod resolver;
pub mod routing;
pub mod storage;
pub mod subscription;
#[cfg_attr(target_os = "macos", path = "platform/macos/system_proxy.rs")]
#[cfg_attr(windows, path = "platform/windows/system_proxy.rs")]
pub mod system_proxy;
#[cfg(target_os = "linux")]
mod tun_routes;
pub mod xray;

pub type Result<T> = std::result::Result<T, String>;
#[cfg(target_os = "linux")]
pub const CORE_VERSION: &str = "1.14.4-eivro.3";
pub const UPSTREAM_CORE_VERSION: &str = "1.14.4";
#[cfg(not(target_os = "linux"))]
pub const CORE_VERSION: &str = UPSTREAM_CORE_VERSION;
pub const MAX_IMPORT: usize = 2 * 1024 * 1024;
#[cfg_attr(target_os = "macos", path = "platform/macos/tun.rs")]
#[cfg_attr(windows, path = "platform/windows/tun.rs")]
pub mod tun;

mod process_profiles;
