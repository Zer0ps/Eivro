use crate::{
    network::{Interface, validate_interface},
    platform::macos::native,
};
pub fn interfaces() -> Vec<Interface> {
    if unsafe { libc::geteuid() } != 0
        && let Ok(mut stream) = crate::tun::connect()
    {
        use crate::platform::macos::wire::{self, Reply, Request};
        if wire::send(&mut stream, &Request::Interfaces {}).is_ok()
            && let Ok(Reply::Interfaces { interfaces }) = wire::receive(&mut stream)
        {
            return interfaces;
        }
    }
    let mut links = raw_interfaces();
    if unsafe { libc::geteuid() } == 0 {
        super::daemon::original_dns(&mut links);
    }
    links
}
fn raw_interfaces() -> Vec<Interface> {
    let Ok(value) = native::interfaces() else {
        return Vec::new();
    };
    let Some(rows) = value.as_array() else {
        return Vec::new();
    };
    let mut links: Vec<_> = rows
        .iter()
        .filter_map(|row| {
            let name = row["name"].as_str()?;
            validate_interface(name).ok()?;
            let dns = row["dns"]
                .as_array()?
                .iter()
                .filter_map(|s| s.as_str()?.parse().ok())
                .collect();
            Some(Interface {
                name: name.into(),
                index: u32::try_from(row["index"].as_u64()?).ok()?,
                up: row["up"].as_bool()?,
                dns,
            })
        })
        .collect();
    links.sort_by(|a, b| a.name.cmp(&b.name));
    links
}
