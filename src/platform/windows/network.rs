use super::native::from_wide;
use crate::{Result, network::Interface};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ptr,
};
use windows_sys::Win32::{
    Foundation::*,
    NetworkManagement::{IpHelper::*, Ndis::*},
    Networking::WinSock::*,
};
pub fn validate_interface(name: &str) -> Result<()> {
    if name.trim().is_empty()
        || name.encode_utf16().count() > 256
        || name.chars().any(char::is_control)
        || name.eq_ignore_ascii_case(crate::platform::TUN_NAME)
        || name.contains(['/', '\\'])
    {
        return Err("Выберите внешний сетевой адаптер Windows.".into());
    }
    Ok(())
}
unsafe fn ip(address: *const SOCKADDR) -> Option<IpAddr> {
    if address.is_null() {
        return None;
    }
    match unsafe { (*address).sa_family } {
        AF_INET => Some(IpAddr::V4(Ipv4Addr::from(
            unsafe { (*address.cast::<SOCKADDR_IN>()).sin_addr.S_un.S_addr }.to_ne_bytes(),
        ))),
        AF_INET6 => Some(IpAddr::V6(Ipv6Addr::from(unsafe {
            (*address.cast::<SOCKADDR_IN6>()).sin6_addr.u.Byte
        }))),
        _ => None,
    }
}
pub fn interfaces() -> Vec<Interface> {
    adapters(false, false).unwrap_or_default()
}
pub(crate) fn adapters(ipv6_index: bool, include_tun: bool) -> Result<Vec<Interface>> {
    let mut size = 16 * 1024;
    for _ in 0..3 {
        // usize storage supplies the alignment required by the linked API structs.
        let mut data = vec![0usize; (size as usize).div_ceil(std::mem::size_of::<usize>())];
        let first = data.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        let status = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC as u32,
                GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
                ptr::null(),
                first,
                &mut size,
            )
        };
        if status == ERROR_BUFFER_OVERFLOW && size <= 1024 * 1024 {
            continue;
        }
        if status != ERROR_SUCCESS {
            return Err("Windows не вернула список адаптеров.".into());
        }
        let mut links = Vec::new();
        let mut current = first;
        while !current.is_null() {
            let row = unsafe { &*current };
            let name = unsafe { from_wide(row.FriendlyName) };
            if row.IfType != IF_TYPE_SOFTWARE_LOOPBACK
                && (validate_interface(&name).is_ok()
                    || include_tun && name.eq_ignore_ascii_case(crate::platform::TUN_NAME))
            {
                let mut dns = Vec::new();
                let mut server = row.FirstDnsServerAddress;
                while !server.is_null() {
                    let value = unsafe { &*server };
                    if let Some(ip) = unsafe { ip(value.Address.lpSockaddr) } {
                        dns.push(ip);
                    }
                    server = value.Next;
                }
                links.push(Interface {
                    name,
                    index: if ipv6_index {
                        row.Ipv6IfIndex
                    } else {
                        unsafe { row.Anonymous1.Anonymous.IfIndex }
                    },
                    up: row.OperStatus == IfOperStatusUp,
                    dns,
                });
            }
            current = row.Next;
        }
        links.sort_by(|a, b| a.name.cmp(&b.name));
        return Ok(links);
    }
    Err("Список адаптеров меняется. Повторите проверку.".into())
}
pub fn uplink(address: IpAddr) -> Result<String> {
    let mut socket: SOCKADDR_INET = unsafe { std::mem::zeroed() };
    match address {
        IpAddr::V4(ip) => {
            socket.Ipv4.sin_family = AF_INET;
            socket.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(ip.octets());
        }
        IpAddr::V6(ip) => {
            socket.Ipv6.sin6_family = AF_INET6;
            socket.Ipv6.sin6_addr.u.Byte = ip.octets();
        }
    }
    let mut index = 0;
    if unsafe { GetBestInterfaceEx((&socket as *const SOCKADDR_INET).cast(), &mut index) } != 0 {
        return Err("Нет маршрута к VPN-серверу.".into());
    }
    adapters(address.is_ipv6(), false)?
        .into_iter()
        .find(|link| link.index == index && link.up)
        .map(|link| link.name)
        .ok_or_else(|| "Не найден внешний адаптер для VPN-сервера.".into())
}
