//! sing-box temporarily disables WeakHostSend for interface-bound sockets.
//! Keep only those pre-existing flags in a private recovery record, so a killed
//! core/service cannot leave a corporate adapter changed. This is not traffic history.
use super::{native, network, storage};
use crate::Result;
use serde::{Deserialize, Serialize};
use std::{fs, io::Read, path::PathBuf};
use windows_sys::Win32::{
    Foundation::ERROR_NOT_FOUND,
    NetworkManagement::{IpHelper::*, Ndis::NET_LUID_LH},
    Networking::WinSock::{AF_INET, AF_INET6},
};
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    luid: u64,
    guid: [u8; 16],
    family: u16,
}
fn location() -> Result<PathBuf> {
    Ok(native::installed_dir()
        .map_err(|_| "Нет каталога службы.")?
        .join("state/windows-network.dat"))
}
fn guid(luid: &NET_LUID_LH) -> Option<[u8; 16]> {
    let mut value = windows_sys::core::GUID::from_u128(0);
    if unsafe { ConvertInterfaceLuidToGuid(luid, &mut value) } != 0 {
        return None;
    }
    // GUID has a fixed 16-byte C layout; the record is local to this machine.
    Some(unsafe { std::mem::transmute::<windows_sys::core::GUID, [u8; 16]>(value) })
}
pub fn recover() -> Result<()> {
    let path = location()?;
    let file = match fs::File::open(&path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err("Не удалось открыть восстановление сетевых адаптеров.".into()),
    };
    let mut bytes = Vec::new();
    file.take(131073)
        .read_to_end(&mut bytes)
        .map_err(|_| "Не удалось прочитать состояние адаптеров.")?;
    if bytes.len() > 131072 {
        return Err("Некорректное состояние адаптеров.".into());
    }
    let entries: Vec<Entry> = serde_json::from_slice(&storage::protect(&bytes, true)?)
        .map_err(|_| "Повреждено состояние восстановления сети.")?;
    if entries.len() > 512 {
        return Err("Некорректное состояние восстановления сети.".into());
    }
    for entry in entries {
        if ![AF_INET, AF_INET6].contains(&entry.family) {
            return Err("Некорректное семейство адресов восстановления.".into());
        }
        let luid = NET_LUID_LH { Value: entry.luid };
        if guid(&luid) != Some(entry.guid) {
            continue;
        }
        let mut row: MIB_IPINTERFACE_ROW = unsafe { std::mem::zeroed() };
        unsafe {
            InitializeIpInterfaceEntry(&mut row);
        }
        row.InterfaceLuid = luid;
        row.Family = entry.family;
        let status = unsafe { GetIpInterfaceEntry(&mut row) };
        if status == ERROR_NOT_FOUND {
            continue;
        }
        if status != 0 {
            return Err("Не удалось проверить адаптер при восстановлении.".into());
        }
        if !row.WeakHostSend {
            row.WeakHostSend = true;
            // GetIpInterfaceEntry may return a nonzero site prefix for IPv4;
            // SetIpInterfaceEntry requires zero even when changing another field.
            if row.Family == AF_INET {
                row.SitePrefixLength = 0;
            }
            let status = unsafe { SetIpInterfaceEntry(&mut row) };
            if status != 0 {
                return Err(format!(
                    "Не удалось восстановить параметры сетевого адаптера (Windows {status})."
                ));
            }
        }
    }
    fs::remove_file(path)
        .map_err(|_| "Сеть восстановлена, но не удалось убрать состояние восстановления.".into())
}
pub struct Lease {
    active: bool,
}
impl Lease {
    pub fn begin() -> Result<Self> {
        recover()?;
        let mut entries = Vec::new();
        for link in network::interfaces() {
            let mut luid: NET_LUID_LH = unsafe { std::mem::zeroed() };
            if unsafe { ConvertInterfaceIndexToLuid(link.index, &mut luid) } != 0 {
                continue;
            }
            let Some(guid) = guid(&luid) else {
                continue;
            };
            for family in [AF_INET, AF_INET6] {
                let mut row: MIB_IPINTERFACE_ROW = unsafe { std::mem::zeroed() };
                unsafe {
                    InitializeIpInterfaceEntry(&mut row);
                }
                row.InterfaceLuid = luid;
                row.Family = family;
                if unsafe { GetIpInterfaceEntry(&mut row) } == 0 && row.WeakHostSend {
                    entries.push(Entry {
                        luid: unsafe { luid.Value },
                        guid,
                        family,
                    });
                }
            }
        }
        if entries.is_empty() {
            return Ok(Self { active: false });
        }
        let bytes = serde_json::to_vec(&entries)
            .map_err(|_| "Не удалось подготовить восстановление сети.")?;
        storage::atomic_write(&location()?, &storage::protect(&bytes, false)?)?;
        Ok(Self { active: true })
    }
    pub fn restore(&mut self) -> Result<()> {
        if self.active {
            recover()?;
            self.active = false;
        }
        Ok(())
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}
