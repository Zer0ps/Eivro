pub mod catalog;
pub mod config;
pub mod connectivity;
#[cfg(feature = "gui")]
#[cfg_attr(target_os = "macos", path = "platform/macos/desktop.rs")]
pub mod desktop;
#[cfg(target_os = "linux")]
pub mod guard;
pub mod import;
pub mod network;
pub mod platform;
pub mod policy;
pub mod privacy;
pub mod process;
pub mod recovery;
pub mod resolver;
pub mod routing;
pub mod storage;
pub mod subscription;
#[cfg_attr(target_os = "macos", path = "platform/macos/system_proxy.rs")]
pub mod system_proxy;
pub mod xray;

pub type Result<T> = std::result::Result<T, String>;
pub const CORE_VERSION: &str = "1.14.4";
pub const MAX_IMPORT: usize = 2 * 1024 * 1024;
#[cfg_attr(target_os = "macos", path = "platform/macos/tun.rs")]
pub mod tun;
