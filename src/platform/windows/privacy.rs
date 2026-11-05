use std::io;
use windows_sys::Win32::System::{
    Diagnostics::Debug::SetErrorMode, ErrorReporting::*, LibraryLoader::*,
};
pub fn harden() -> io::Result<()> {
    std::panic::set_hook(Box::new(|_| {}));
    unsafe {
        // Process-local only. Do not change Windows Defender or global WER policy.
        SetErrorMode(0x0001 | 0x0002 | 0x8000);
        if SetDefaultDllDirectories(
            LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
        if WerSetFlags(
            WER_FAULT_REPORTING_FLAG_NOHEAP
                | WER_FAULT_REPORTING_NO_UI
                | WER_FAULT_REPORTING_DISABLE_SNAPSHOT_CRASH
                | WER_FAULT_REPORTING_DISABLE_SNAPSHOT_HANG,
        ) < 0
        {
            return Err(io::Error::other("Cannot configure process crash reporting"));
        }
    }
    Ok(())
}
pub fn silence_stdio() -> io::Result<()> {
    use std::{fs::OpenOptions, os::windows::io::AsRawHandle};
    use windows_sys::Win32::System::Console::*;
    let null = OpenOptions::new().write(true).open("NUL")?;
    unsafe {
        SetStdHandle(STD_OUTPUT_HANDLE, null.as_raw_handle());
        SetStdHandle(STD_ERROR_HANDLE, null.as_raw_handle());
    }
    // Standard handles are process-owned until termination.
    std::mem::forget(null);
    Ok(())
}
