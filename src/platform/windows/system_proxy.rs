//! Per-user WinINET lease. Its watchdog outlives the GUI just long enough to
//! restore the previous settings; a DPAPI-protected journal covers watchdog loss.
use crate::{
    Result,
    platform::windows::{
        native::{self, SecurityDescriptor, owned, raw, user_sid, wide},
        storage,
    },
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Write},
    os::windows::io::OwnedHandle,
    path::PathBuf,
    ptr,
};
use windows_sys::Win32::{Foundation::*, Networking::WinInet::*, System::Threading::*};
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Proxy {
    flags: u32,
    server: String,
    bypass: String,
    auto_url: String,
}
#[derive(Serialize, Deserialize)]
struct Journal {
    before: Proxy,
    applied: Proxy,
}
struct Lock(OwnedHandle);
impl Drop for Lock {
    fn drop(&mut self) {
        unsafe {
            ReleaseMutex(raw(&self.0));
        }
    }
}
fn lock() -> Result<Option<Lock>> {
    let sid = user_sid().map_err(|_| "Не удалось определить пользователя прокси.")?;
    let sd = SecurityDescriptor::new(&format!("D:P(A;;GA;;;SY)(A;;GA;;;{sid})"))
        .map_err(|_| "Нет прав канала прокси.")?;
    let handle = unsafe {
        owned(CreateMutexW(
            &sd.attributes(),
            0,
            wide(format!("Global\\Eivro-Proxy-{sid}")).as_ptr(),
        ))
    }
    .map_err(|_| "Не удалось заблокировать настройки прокси.")?;
    match unsafe { WaitForSingleObject(raw(&handle), 0) } {
        WAIT_OBJECT_0 | WAIT_ABANDONED => Ok(Some(Lock(handle))),
        WAIT_TIMEOUT => Ok(None),
        _ => Err("Ошибка блокировки настроек прокси.".into()),
    }
}
fn journal_path() -> Result<PathBuf> {
    Ok(crate::storage::default_path()?.with_file_name("proxy-recovery.dat"))
}
fn options() -> [INTERNET_PER_CONN_OPTIONW; 4] {
    [
        INTERNET_PER_CONN_FLAGS,
        INTERNET_PER_CONN_PROXY_SERVER,
        INTERNET_PER_CONN_PROXY_BYPASS,
        INTERNET_PER_CONN_AUTOCONFIG_URL,
    ]
    .map(|dw_option| INTERNET_PER_CONN_OPTIONW {
        dwOption: dw_option,
        Value: unsafe { std::mem::zeroed() },
    })
}
fn list(options: &mut [INTERNET_PER_CONN_OPTIONW; 4]) -> INTERNET_PER_CONN_OPTION_LISTW {
    INTERNET_PER_CONN_OPTION_LISTW {
        dwSize: std::mem::size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
        pszConnection: ptr::null_mut(),
        dwOptionCount: 4,
        dwOptionError: 0,
        pOptions: options.as_mut_ptr(),
    }
}
fn read() -> Result<Proxy> {
    let mut options = options();
    let mut list = list(&mut options);
    let mut size = std::mem::size_of_val(&list) as u32;
    if unsafe {
        InternetQueryOptionW(
            ptr::null_mut(),
            INTERNET_OPTION_PER_CONNECTION_OPTION,
            (&mut list as *mut INTERNET_PER_CONN_OPTION_LISTW).cast(),
            &mut size,
        )
    } == 0
    {
        return Err("Не удалось прочитать системный прокси Windows.".into());
    }
    let strings = options[1..]
        .iter()
        .map(|option| unsafe {
            let p = option.Value.pszValue;
            let text = native::from_wide(p);
            if !p.is_null() {
                GlobalFree(p.cast());
            }
            text
        })
        .collect::<Vec<_>>();
    Ok(Proxy {
        flags: unsafe { options[0].Value.dwValue },
        server: strings[0].clone(),
        bypass: strings[1].clone(),
        auto_url: strings[2].clone(),
    })
}
fn apply(proxy: &Proxy) -> Result<()> {
    let mut strings = [
        wide(&proxy.server),
        wide(&proxy.bypass),
        wide(&proxy.auto_url),
    ];
    let mut options = options();
    options[0].Value.dwValue = proxy.flags;
    for (option, text) in options[1..].iter_mut().zip(strings.iter_mut()) {
        option.Value.pszValue = text.as_mut_ptr();
    }
    let mut list = list(&mut options);
    unsafe {
        if InternetSetOptionW(
            ptr::null_mut(),
            INTERNET_OPTION_PER_CONNECTION_OPTION,
            (&mut list as *mut INTERNET_PER_CONN_OPTION_LISTW).cast(),
            std::mem::size_of_val(&list) as u32,
        ) == 0
        {
            return Err("Windows не удалось изменить системный прокси.".into());
        }
        if InternetSetOptionW(
            ptr::null_mut(),
            INTERNET_OPTION_SETTINGS_CHANGED,
            ptr::null(),
            0,
        ) == 0
            || InternetSetOptionW(ptr::null_mut(), INTERNET_OPTION_REFRESH, ptr::null(), 0) == 0
        {
            return Err("Не удалось уведомить приложения об изменении прокси.".into());
        }
    }
    Ok(())
}
fn restoration(current: &Proxy, journal: &Journal) -> Proxy {
    // Another proxy client or a manual setting owns the configuration now.
    if current.server != journal.applied.server || current.flags != journal.applied.flags {
        return current.clone();
    }
    let mut restored = journal.before.clone();
    if current.bypass != journal.applied.bypass {
        restored.bypass = current.bypass.clone();
    }
    if current.auto_url != journal.applied.auto_url {
        restored.auto_url = current.auto_url.clone();
    }
    restored
}
fn restore() -> Result<()> {
    let path = journal_path()?;
    let file = match fs::File::open(&path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err("Не удалось открыть состояние восстановления прокси.".into()),
    };
    let mut bytes = Vec::new();
    file.take(131073)
        .read_to_end(&mut bytes)
        .map_err(|_| "Не удалось прочитать состояние прокси.")?;
    if bytes.len() > 131072 {
        return Err("Некорректное состояние восстановления прокси.".into());
    }
    let journal: Journal = serde_json::from_slice(&storage::protect(&bytes, true)?)
        .map_err(|_| "Повреждено состояние восстановления прокси.")?;
    let current = read()?;
    let desired = restoration(&current, &journal);
    if desired != current {
        apply(&desired)?;
    }
    fs::remove_file(path)
        .map_err(|_| "Прокси восстановлен, но не удалось убрать файл восстановления.".into())
}
pub fn recover_stale() -> Result<()> {
    let Some(_lock) = lock()? else {
        return Ok(());
    };
    restore()
}
pub fn guard(port: u16) -> Result<bool> {
    if port < 1024 {
        return Err("Некорректный порт прокси.".into());
    }
    let _lock = lock()?.ok_or("Системный прокси уже используется другим Eivro.")?;
    restore()?;
    let before = read()?;
    let applied = Proxy {
        flags: PROXY_TYPE_DIRECT | PROXY_TYPE_PROXY,
        server: format!("http=127.0.0.1:{port};https=127.0.0.1:{port};socks=127.0.0.1:{port}"),
        bypass: "localhost;127.*;[::1]".into(),
        auto_url: String::new(),
    };
    let journal = Journal {
        before,
        applied: applied.clone(),
    };
    let bytes = serde_json::to_vec(&journal)
        .map_err(|_| "Не удалось подготовить восстановление прокси.")?;
    storage::atomic_write(&journal_path()?, &storage::protect(&bytes, false)?)?;
    let result = (|| {
        apply(&applied)?;
        std::io::stdout()
            .write_all(b"READY\n")
            .and_then(|_| std::io::stdout().flush())
            .map_err(|_| "Нет канала подтверждения прокси.")?;
        let mut byte = [0];
        loop {
            match std::io::stdin().read(&mut byte) {
                Ok(0) => break,
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        Ok(true)
    })();
    let restored = restore();
    restored.and(result)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn sample(server: &str) -> Proxy {
        Proxy {
            flags: 3,
            server: server.into(),
            bypass: "localhost".into(),
            auto_url: String::new(),
        }
    }
    #[test]
    fn restore_keeps_external_proxy_and_manual_bypass() {
        let journal = Journal {
            before: sample("original"),
            applied: sample("eivro"),
        };
        let external = sample("other-client");
        assert_eq!(restoration(&external, &journal), external);
        let mut current = journal.applied.clone();
        current.bypass = "custom".into();
        let restored = restoration(&current, &journal);
        assert_eq!(restored.server, "original");
        assert_eq!(restored.bypass, "custom");
    }

    #[test]
    #[ignore = "Temporarily changes WinINET settings in an explicitly authorized disposable lab"]
    fn windows_lab_proxy_watchdog_restores_after_eof_crash_and_preserves_external_owner() {
        use std::{
            process::{Child, Stdio},
            time::{Duration, Instant},
        };
        assert_eq!(std::env::var("EIVRO_WINDOWS_LAB").as_deref(), Ok("1"));
        assert!(
            !journal_path().unwrap().exists(),
            "Existing recovery must not be overwritten by the test"
        );
        let original = read().unwrap();
        struct Restore(Proxy);
        impl Drop for Restore {
            fn drop(&mut self) {
                if apply(&self.0).is_ok() {
                    let _ = fs::remove_file(journal_path().unwrap());
                }
            }
        }
        let _restore = Restore(original.clone());
        fn start() -> Child {
            let mut child = crate::process::child_command(&crate::process::app_path().unwrap())
                .args(["--proxy-guard", "32191"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(8);
            loop {
                let mut count = 0;
                unsafe {
                    windows_sys::Win32::System::Pipes::PeekNamedPipe(
                        raw(child.stdout.as_ref().unwrap()),
                        ptr::null_mut(),
                        0,
                        ptr::null_mut(),
                        &mut count,
                        ptr::null_mut(),
                    );
                }
                if count >= 6 {
                    break;
                }
                assert!(
                    child.try_wait().unwrap().is_none(),
                    "Proxy watchdog exited before READY"
                );
                assert!(Instant::now() < deadline, "Proxy watchdog did not start");
                std::thread::sleep(Duration::from_millis(20));
            }
            let mut ready = [0; 6];
            child
                .stdout
                .as_mut()
                .unwrap()
                .read_exact(&mut ready)
                .unwrap();
            assert_eq!(&ready, b"READY\n");
            child
        }
        fn stop(mut child: Child) {
            child.stdin.take();
            if native::wait(&[raw(&child)], 8000).unwrap().is_none() {
                child.kill().unwrap();
                panic!("Proxy watchdog failed to stop");
            }
            assert!(child.wait().unwrap().success());
        }
        let child = start();
        assert!(read().unwrap().server.contains("127.0.0.1:32191"));
        stop(child);
        assert_eq!(read().unwrap(), original);

        let mut crashed = start();
        crashed.kill().unwrap();
        crashed.wait().unwrap();
        recover_stale().unwrap();
        assert_eq!(read().unwrap(), original);
        assert!(!journal_path().unwrap().exists());

        let child = start();
        let mut external = read().unwrap();
        external.server = "http=127.0.0.1:32192;https=127.0.0.1:32192".into();
        apply(&external).unwrap();
        stop(child);
        assert_eq!(read().unwrap(), external);
    }
}
