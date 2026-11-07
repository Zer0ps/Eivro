//! Settings are atomically replaced and protected with the current user's DPAPI
//! key. Subscriptions and UUIDs never appear in a plaintext temporary file.
use super::native::{SecurityDescriptor, from_wide, user_sid, wide};
use crate::{Result, storage::Settings};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    ptr,
};
use windows_sys::Win32::{
    Foundation::LocalFree,
    Security::{Authorization::*, Cryptography::*, *},
    Storage::FileSystem::*,
    System::Com::CoTaskMemFree,
    UI::Shell::*,
};
const LIMIT: usize = 16 * 1024 * 1024;
pub fn default_path() -> Result<PathBuf> {
    let mut text = ptr::null_mut();
    if unsafe { SHGetKnownFolderPath(&FOLDERID_LocalAppData, 0, ptr::null_mut(), &mut text) } < 0 {
        return Err("Нет каталога настроек Windows.".into());
    }
    let base = PathBuf::from(unsafe { from_wide(text) });
    unsafe {
        CoTaskMemFree(text.cast());
    }
    #[cfg(feature = "qa")]
    let base = std::env::var_os("EIVRO_QA_HOME")
        .map(PathBuf::from)
        .unwrap_or(base);
    Ok(base.join("Eivro/settings.dat"))
}
pub fn instance_scope() -> Result<PathBuf> {
    default_path()
}
pub fn prepare_config() -> Result<PathBuf> {
    default_path()
}
pub(crate) fn protect(data: &[u8], decrypt: bool) -> Result<Vec<u8>> {
    if data.len() > LIMIT + 65536 {
        return Err("Файл настроек слишком большой.".into());
    }
    let input = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr().cast_mut(),
    };
    let mut output: CRYPT_INTEGER_BLOB = unsafe { std::mem::zeroed() };
    let ok = unsafe {
        if decrypt {
            CryptUnprotectData(
                &input,
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        } else {
            CryptProtectData(
                &input,
                wide("Eivro").as_ptr(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        }
    };
    if ok == 0 {
        return Err("Windows не удалось защитить или открыть настройки этого пользователя.".into());
    }
    let bytes =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) }.to_vec();
    unsafe {
        LocalFree(output.pbData.cast());
    }
    Ok(bytes)
}
pub fn load(path: &Path) -> Result<Settings> {
    let file = match fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Settings::default()),
        Err(_) => return Err("Не удалось открыть настройки.".into()),
    };
    let mut encrypted = Vec::new();
    file.take((LIMIT + 65537) as u64)
        .read_to_end(&mut encrypted)
        .map_err(|_| "Не удалось прочитать настройки.")?;
    let data = protect(&encrypted, true)?;
    let mut settings: Settings = serde_json::from_slice(&data)
        .map_err(|_| "Файл настроек повреждён; автоматическая перезапись отключена.")?;
    settings.migrate()?;
    Ok(settings)
}
pub(crate) fn private_directory(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir).map_err(|_| "Не удалось создать каталог настроек.")?;
    let attributes = unsafe { GetFileAttributesW(wide(dir).as_ptr()) };
    if attributes == INVALID_FILE_ATTRIBUTES || attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err("Небезопасный каталог настроек.".into());
    }
    let sid = user_sid().map_err(|_| "Нет пользователя Windows.")?;
    let descriptor = SecurityDescriptor::new(&format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{sid})"))
        .map_err(|_| "Не удалось подготовить права настроек.")?;
    let mut present = 0;
    let mut defaulted = 0;
    let mut dacl = ptr::null_mut();
    if unsafe { GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut dacl, &mut defaulted) }
        == 0
        || present == 0
    {
        return Err("Не удалось проверить права настроек.".into());
    }
    if unsafe {
        SetNamedSecurityInfoW(
            wide(dir).as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            dacl,
            ptr::null(),
        )
    } != 0
    {
        return Err("Не удалось ограничить доступ к настройкам.".into());
    }
    Ok(())
}
pub(crate) fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    let dir = path.parent().ok_or("Нет каталога настроек.")?;
    private_directory(dir)?;
    let mut random = [0u8; 16];
    if unsafe {
        BCryptGenRandom(
            ptr::null_mut(),
            random.as_mut_ptr(),
            16,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    } < 0
    {
        return Err("Нет источника случайных чисел Windows.".into());
    }
    let name: String = random.iter().map(|b| format!("{b:02x}")).collect();
    let temp = dir.join(format!(".{name}.tmp"));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .map_err(|_| "Не удалось создать файл настроек.")?;
        file.write_all(data)
            .and_then(|_| file.sync_all())
            .map_err(|_| "Не удалось сохранить настройки.")?;
        drop(file);
        if unsafe {
            MoveFileExW(
                wide(&temp).as_ptr(),
                wide(path).as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            return Err("Не удалось заменить настройки.".into());
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}
pub fn save(path: &Path, settings: &Settings) -> Result<()> {
    settings.validate()?;
    let bytes = serde_json::to_vec(settings).map_err(|_| "Не удалось подготовить настройки.")?;
    if bytes.len() > LIMIT {
        return Err("Файл настроек слишком большой.".into());
    }
    let previous_file = match fs::File::open(path) {
        Ok(file) => Some(file),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => return Err("Не удалось проверить прежние настройки.".into()),
    };
    if let Some(file) = previous_file {
        let mut previous = Vec::new();
        file.take((LIMIT + 65537) as u64)
            .read_to_end(&mut previous)
            .map_err(|_| "Не удалось прочитать прежние настройки.")?;
        let old: serde_json::Value = serde_json::from_slice(&protect(&previous, true)?)
            .map_err(|_| "Прежние настройки повреждены.")?;
        if let Some(schema) = old["schema"]
            .as_u64()
            .filter(|schema| *schema < u64::from(crate::storage::SCHEMA))
        {
            let dir = path.parent().ok_or("Нет каталога настроек.")?;
            private_directory(dir)?;
            let backup = dir.join(if schema == 5 {
                "settings-before-1.5.0.dat"
            } else {
                "settings-before-1.3.2.dat"
            });
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&backup)
            {
                Ok(mut file) => {
                    if file
                        .write_all(&previous)
                        .and_then(|_| file.sync_all())
                        .is_err()
                    {
                        let _ = fs::remove_file(&backup);
                        return Err("Не удалось сохранить настройки для отката.".into());
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(_) => return Err("Не удалось сохранить настройки для отката.".into()),
            }
        }
    }
    atomic_write(path, &protect(&bytes, false)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dpapi_roundtrip_rejects_modified_ciphertext() {
        let plaintext = b"synthetic UUID and subscription credentials";
        let mut encrypted = protect(plaintext, false).unwrap();
        assert!(
            !encrypted
                .windows(plaintext.len())
                .any(|window| window == plaintext)
        );
        assert_eq!(protect(&encrypted, true).unwrap(), plaintext);
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0x80;
        assert!(protect(&encrypted, true).is_err());
    }
    #[test]
    fn settings_replace_atomically_and_remain_private() {
        let dir = std::env::temp_dir().join(format!("eivro-settings-test-{}", std::process::id()));
        let path = dir.join("settings.dat");
        let mut settings = Settings::default();
        save(&path, &settings).unwrap();
        settings.port = 23456;
        save(&path, &settings).unwrap();
        assert_eq!(load(&path).unwrap().port, 23456);
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn preset_migration_preserves_an_encrypted_rollback_copy() {
        let dir = std::env::temp_dir().join(format!("eivro-schema5-backup-{}", std::process::id()));
        let path = dir.join("settings.dat");
        let old = Settings {
            schema: 4,
            routing_profiles: vec![Default::default()],
            ..Settings::default()
        };
        let encrypted = protect(&serde_json::to_vec(&old).unwrap(), false).unwrap();
        atomic_write(&path, &encrypted).unwrap();
        let migrated = load(&path).unwrap();
        save(&path, &migrated).unwrap();
        assert_eq!(
            fs::read(dir.join("settings-before-1.3.2.dat")).unwrap(),
            encrypted
        );
        assert_eq!(load(&path).unwrap().routing_profiles.len(), 3);
        fs::remove_dir_all(dir).unwrap();
    }
}
