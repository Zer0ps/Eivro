pub mod catalog;
pub mod config;
pub mod connectivity;
#[cfg(feature = "gui")]
pub mod desktop;
pub mod guard;
pub mod import;
pub mod network;
pub mod policy;
pub mod privacy;
pub mod process;
pub mod recovery;
pub mod resolver;
pub mod routing;
pub mod storage;
pub mod subscription;
pub mod system_proxy;
pub mod xray;

pub type Result<T> = std::result::Result<T, String>;
pub const CORE_VERSION: &str = "1.14.4";
pub const MAX_IMPORT: usize = 2 * 1024 * 1024;
pub mod tun;
