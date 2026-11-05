//! Small owning wrappers around Windows objects. Every steady-state wait is
//! kernel-backed; no timer is needed to notice cancellation or process exit.
use std::{
    ffi::OsStr,
    io,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::{Path, PathBuf},
    ptr,
    sync::Arc,
};
use windows_sys::Win32::{
    Foundation::*,
    Security::Authorization::*,
    Security::*,
    System::{
        JobObjects::*,
        SystemServices::{ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE},
        Threading::*,
    },
};

pub fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(Some(0)).collect()
}
/// # Safety
/// A non-null successful handle must be uniquely owned and closeable with CloseHandle.
pub unsafe fn owned(handle: HANDLE) -> io::Result<OwnedHandle> {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
    }
}
pub fn raw(handle: &impl AsRawHandle) -> HANDLE {
    handle.as_raw_handle()
}
#[derive(Clone)]
pub struct Event(Arc<OwnedHandle>);
impl Event {
    pub fn new() -> io::Result<Self> {
        Ok(Self(Arc::new(unsafe {
            owned(CreateEventW(ptr::null(), 1, 0, ptr::null()))
        }?)))
    }
    pub fn set(&self) {
        unsafe {
            SetEvent(raw(&*self.0));
        }
    }
    pub fn handle(&self) -> HANDLE {
        raw(&*self.0)
    }
    pub fn signaled(&self) -> bool {
        unsafe { WaitForSingleObject(self.handle(), 0) == WAIT_OBJECT_0 }
    }
}
pub fn wait(handles: &[HANDLE], timeout: u32) -> io::Result<Option<usize>> {
    if handles.is_empty() || handles.len() > 64 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let result =
        unsafe { WaitForMultipleObjects(handles.len() as u32, handles.as_ptr(), 0, timeout) };
    if result == WAIT_TIMEOUT {
        Ok(None)
    } else if result < WAIT_OBJECT_0 + handles.len() as u32 {
        Ok(Some((result - WAIT_OBJECT_0) as usize))
    } else {
        Err(io::Error::last_os_error())
    }
}
pub struct SecurityDescriptor(pub PSECURITY_DESCRIPTOR);
impl SecurityDescriptor {
    pub fn new(sddl: &str) -> io::Result<Self> {
        let mut p = ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide(sddl).as_ptr(),
                1,
                &mut p,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(p))
    }
    pub fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0,
            bInheritHandle: 0,
        }
    }
}
impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}
pub fn user_sid() -> io::Result<String> {
    sid_for_process(unsafe { GetCurrentProcess() })
}
pub fn installation_user_sid() -> io::Result<String> {
    use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
    use windows_sys::Win32::UI::WindowsAndMessaging::{GetShellWindow, GetWindowThreadProcessId};
    let shell = unsafe { GetShellWindow() };
    if shell.is_null() {
        return user_sid();
    }
    // Over-the-shoulder UAC runs Setup as a different administrator. Grant the
    // original desktop user, identified by a process token, not a supplied name.
    let mut pid = 0;
    let mut shell_session = 0;
    let mut current_session = 0;
    if unsafe { GetWindowThreadProcessId(shell, &mut pid) } == 0
        || unsafe { ProcessIdToSessionId(pid, &mut shell_session) } == 0
        || unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut current_session) } == 0
        || shell_session != current_session
    {
        return Err(io::Error::other(
            "Cannot identify the installation's desktop user",
        ));
    }
    let token_sid = (|| {
        let process = unsafe { owned(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid)) }?;
        sid_for_process(raw(&process))
    })();
    match token_sid {
        Ok(sid) => Ok(sid),
        // A different admin may not query Explorer's token without SeDebug.
        // Use the OS-owned session identity instead of enabling that privilege.
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            session_user_sid(current_session)
        }
        Err(error) => Err(error),
    }
}
fn session_user_sid(session: u32) -> io::Result<String> {
    use windows_sys::Win32::System::RemoteDesktop::*;
    fn query(session: u32, field: WTS_INFO_CLASS) -> io::Result<String> {
        let mut value = ptr::null_mut();
        let mut bytes = 0;
        if unsafe {
            WTSQuerySessionInformationW(ptr::null_mut(), session, field, &mut value, &mut bytes)
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let result = if value.is_null() || !(2..=65536).contains(&bytes) {
            Err(io::ErrorKind::InvalidData.into())
        } else {
            Ok(unsafe { from_wide(value) })
        };
        unsafe {
            WTSFreeMemory(value.cast());
        }
        result
    }
    let user = query(session, WTSUserName)?;
    let domain = query(session, WTSDomainName)?;
    if user.is_empty() {
        return Err(io::ErrorKind::NotFound.into());
    }
    let account = wide(if domain.is_empty() {
        user
    } else {
        format!("{domain}\\{user}")
    });
    let mut sid_size = 0;
    let mut domain_size = 0;
    let mut kind = 0;
    unsafe {
        LookupAccountNameW(
            ptr::null(),
            account.as_ptr(),
            ptr::null_mut(),
            &mut sid_size,
            ptr::null_mut(),
            &mut domain_size,
            &mut kind,
        );
    }
    if !(1..=256).contains(&sid_size) || domain_size > 32768 {
        return Err(io::Error::last_os_error());
    }
    let mut sid = vec![0u32; (sid_size as usize).div_ceil(4)];
    let mut domain = vec![0u16; domain_size as usize];
    if unsafe {
        LookupAccountNameW(
            ptr::null(),
            account.as_ptr(),
            sid.as_mut_ptr().cast(),
            &mut sid_size,
            domain.as_mut_ptr(),
            &mut domain_size,
            &mut kind,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if kind != SidTypeUser {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    sid_string(sid.as_mut_ptr().cast())
}
fn sid_for_process(process: HANDLE) -> io::Result<String> {
    let mut token = ptr::null_mut();
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = unsafe { owned(token) }?;
    let mut size = 0;
    unsafe {
        GetTokenInformation(raw(&token), TokenUser, ptr::null_mut(), 0, &mut size);
    }
    let mut bytes = vec![0usize; (size as usize).div_ceil(std::mem::size_of::<usize>())];
    if unsafe {
        GetTokenInformation(
            raw(&token),
            TokenUser,
            bytes.as_mut_ptr().cast(),
            size,
            &mut size,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let sid = unsafe { (*(bytes.as_ptr().cast::<TOKEN_USER>())).User.Sid };
    sid_string(sid)
}
fn sid_string(sid: PSID) -> io::Result<String> {
    let mut text = ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let result = unsafe { from_wide(text) };
    unsafe {
        LocalFree(text.cast());
    }
    Ok(result)
}
/// # Safety
/// `p` must be null or point to a valid NUL-terminated UTF-16 API string,
/// readable for its full length (at most 32768 code units).
pub unsafe fn from_wide(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let len = (0..32768)
        .take_while(|&i| unsafe { *p.add(i) != 0 })
        .count();
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, len) })
}
pub struct Job(OwnedHandle);
impl Job {
    pub fn new() -> io::Result<Self> {
        let handle = unsafe { owned(CreateJobObjectW(ptr::null(), ptr::null())) }?;
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if unsafe {
            SetInformationJobObject(
                raw(&handle),
                JobObjectExtendedLimitInformation,
                (&info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of_val(&info) as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(handle))
    }
    pub fn assign(&self, child: &impl AsRawHandle) -> io::Result<()> {
        if unsafe { AssignProcessToJobObject(raw(&self.0), raw(child)) } == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}
pub fn installed_dir() -> io::Result<PathBuf> {
    use windows_sys::Win32::{
        System::Com::CoTaskMemFree,
        UI::Shell::{FOLDERID_ProgramFiles, SHGetKnownFolderPath},
    };
    let mut p = ptr::null_mut();
    if unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramFiles, 0, ptr::null_mut(), &mut p) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let path = PathBuf::from(unsafe { from_wide(p) }).join("Eivro");
    unsafe {
        CoTaskMemFree(p.cast());
    }
    Ok(path)
}
pub fn protected_binary(path: &Path) -> bool {
    use windows_sys::Win32::Storage::FileSystem::*;
    let Ok(root) = installed_dir() else {
        return false;
    };
    if path.parent() != Some(root.as_path()) || !path.is_file() {
        return false;
    }
    [root.as_path(), path].into_iter().all(|p| unsafe {
        let p = wide(p);
        let attributes = GetFileAttributesW(p.as_ptr());
        if attributes == INVALID_FILE_ATTRIBUTES || attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return false;
        }
        let mut descriptor = ptr::null_mut();
        let mut dacl = ptr::null_mut();
        let mut owner = ptr::null_mut();
        if GetNamedSecurityInfoW(
            p.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut descriptor,
        ) != ERROR_SUCCESS
        {
            return false;
        }
        let _free = SecurityDescriptor(descriptor);
        if owner.is_null()
            || dacl.is_null()
            || (IsWellKnownSid(owner, WinLocalSystemSid) == 0
                && IsWellKnownSid(owner, WinBuiltinAdministratorsSid) == 0)
        {
            return false;
        }
        for i in 0..(*dacl).AceCount {
            let mut ace = ptr::null_mut();
            if GetAce(dacl, i as u32, &mut ace) == 0 {
                return false;
            }
            let head = &*ace.cast::<ACE_HEADER>();
            if head.AceType == ACCESS_ALLOWED_ACE_TYPE as u8 {
                let ace = &*ace.cast::<ACCESS_ALLOWED_ACE>();
                let sid = (&ace.SidStart as *const u32).cast_mut().cast();
                let write = FILE_WRITE_DATA
                    | FILE_APPEND_DATA
                    | FILE_WRITE_EA
                    | FILE_WRITE_ATTRIBUTES
                    | DELETE
                    | WRITE_DAC
                    | WRITE_OWNER
                    | FILE_DELETE_CHILD
                    | GENERIC_WRITE
                    | GENERIC_ALL;
                if ace.Mask & write != 0
                    && IsWellKnownSid(sid, WinLocalSystemSid) == 0
                    && IsWellKnownSid(sid, WinBuiltinAdministratorsSid) == 0
                {
                    return false;
                }
            } else if head.AceType != ACCESS_DENIED_ACE_TYPE as u8 {
                return false;
            }
        }
        true
    })
}

/// Capture running application paths once when the rule editor opens. Windows
/// may deny access to protected/system processes; they are not rule suggestions.
pub fn applications() -> Vec<(String, String)> {
    use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
    let Ok(snapshot) = (unsafe { owned(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)) }) else {
        return Vec::new();
    };
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of_val(&entry) as u32;
    let mut found = std::collections::BTreeMap::new();
    let mut next = unsafe { Process32FirstW(raw(&snapshot), &mut entry) } != 0;
    while next {
        if let Ok(process) = unsafe {
            owned(OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION,
                0,
                entry.th32ProcessID,
            ))
        } {
            let mut text = vec![0u16; 32768];
            let mut size = text.len() as u32;
            if unsafe { QueryFullProcessImageNameW(raw(&process), 0, text.as_mut_ptr(), &mut size) }
                != 0
            {
                let path = String::from_utf16_lossy(&text[..size as usize]);
                if crate::policy::Target::application(&path).is_ok() {
                    let name = Path::new(&path)
                        .file_stem()
                        .map(|s| s.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    found.entry(path.to_lowercase()).or_insert((name, path));
                }
            }
        }
        next = unsafe { Process32NextW(raw(&snapshot), &mut entry) } != 0;
    }
    let mut apps: Vec<_> = found.into_values().collect();
    apps.sort_by_cached_key(|app| app.0.to_lowercase());
    apps
}

#[cfg(feature = "gui")]
pub fn initial_viewport() -> eframe::egui::ViewportBuilder {
    use windows_sys::Win32::{
        Graphics::Gdi::*,
        UI::{HiDpi::*, WindowsAndMessaging::*},
    };
    unsafe {
        SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    }
    let mut cursor = POINT { x: 0, y: 0 };
    unsafe {
        GetCursorPos(&mut cursor);
    }
    let monitor = unsafe { MonitorFromPoint(cursor, MONITOR_DEFAULTTONEAREST) };
    let mut info: MONITORINFO = unsafe { std::mem::zeroed() };
    info.cbSize = std::mem::size_of_val(&info) as u32;
    let mut viewport = eframe::egui::ViewportBuilder::default()
        .with_title("Eivro")
        .with_app_id("io.eivro.Client")
        .with_inner_size([960.0, 700.0])
        .with_min_inner_size([700.0, 480.0]);
    if unsafe { GetMonitorInfoW(monitor, &mut info) } != 0 {
        let mut x = 96;
        let mut y = 96;
        unsafe {
            GetDpiForMonitor(monitor, MDT_EFFECTIVE_DPI, &mut x, &mut y);
        }
        let scale = x.max(96) as f32 / 96.0;
        let work = info.rcWork;
        let width = ((work.right - work.left) as f32 / scale - 24.0).clamp(320.0, 960.0);
        let height = ((work.bottom - work.top) as f32 / scale - 64.0).clamp(240.0, 760.0);
        viewport = viewport
            .with_inner_size([width, height])
            .with_min_inner_size([width.min(700.0), height.min(480.0)])
            .with_position([
                work.left as f32 / scale + ((work.right - work.left) as f32 / scale - width) / 2.0,
                work.top as f32 / scale + 12.0,
            ]);
    }
    if let Ok(icon) =
        eframe::icon_data::from_png_bytes(include_bytes!("../../../assets/io.eivro.Client.png"))
    {
        viewport = viewport.with_icon(std::sync::Arc::new(icon));
    }
    viewport
}
