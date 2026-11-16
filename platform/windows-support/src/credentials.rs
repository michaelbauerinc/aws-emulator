// SPDX-License-Identifier: CC0-1.0

//! Private Windows files for the emulator's credentials and client configuration.
//!
//! A protected DACL granting only the current process user full control is supplied
//! at creation. After opening the volume/share root, every operation uses a held
//! directory handle and one validated name. Reparse points are opened as entries,
//! never followed. Ancestors are retained without delete sharing and rechecked
//! before publication. Existing port directories must already have a private ACL;
//! an inherited or broader ACL is refused.

use std::ffi::{c_void, OsStr, OsString};
use std::io::{self, Write};
use std::mem::{size_of, MaybeUninit};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Component, Path, PathBuf, Prefix};
use std::ptr::{null, null_mut};

use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    NtCreateFile, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN,
    FILE_OPEN_IF, FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT,
};
use windows_sys::Win32::Foundation::{
    LocalFree, RtlNtStatusToDosError, ERROR_FILE_NOT_FOUND, ERROR_INSUFFICIENT_BUFFER,
    GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, OBJ_CASE_INSENSITIVE, UNICODE_STRING,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    GetAce, GetSecurityDescriptorControl, GetTokenInformation, TokenUser, ACCESS_ALLOWED_ACE,
    ACE_HEADER, ACL, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, OBJECT_INHERIT_ACE,
    OWNER_SECURITY_INFORMATION, PSID, SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FileDispositionInfo, FileIdInfo, GetFileInformationByHandle,
    GetFileInformationByHandleEx, ReOpenFile, SetFileInformationByHandle,
    BY_HANDLE_FILE_INFORMATION, DELETE, FILE_ALL_ACCESS, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_DISPOSITION_INFO,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_INFO, FILE_READ_ATTRIBUTES,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, READ_CONTROL, SYNCHRONIZE,
};
use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::Win32::System::WindowsProgramming::FILE_CREATED;
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

/// Write one private file, replacing an existing ordinary, single-link file.
///
/// Current limitation: drop the previous guard before replacing the same name. If
/// an existing handle delays an accepted deletion, replacement fails and the old
/// name can remain delete-pending and unreadable until that handle closes.
///
/// `folder` must be absolute. Missing directories are created privately; the final
/// directory must be owned by this user with a protected owner-only DACL. Reparse
/// points, hard-linked destination files, device names, and alternate streams are
/// refused. A competing creator causes `CREATE_NEW` to fail rather than following
/// or overwriting the competing entry. No credential bytes are written until the
/// new file's ACL has been verified through its open handle. Keep the returned guard
/// alive while clients use the file. Dropping it removes only the same file identity;
/// a replacement entry is left untouched. Directory handles anchor creation and
/// cleanup even if an empty ancestor is concurrently changed into a junction.
pub fn write_private_file(folder: &Path, name: &str, bytes: &[u8]) -> io::Result<PrivateFile> {
    validate_component(OsStr::new(name))?;
    let user = current_user_sid()?;
    let directory_security = SecurityDescriptor::owner_only(&user, true)?;
    let file_security = SecurityDescriptor::owner_only(&user, false)?;
    let directories = lock_directories(folder, &directory_security, &user)?;
    let name = OsStr::new(name);
    remove_existing_file(directories.last(), name)?;
    let (handle, _) = open_relative(
        directories.last(),
        name,
        RelativeOpen {
            access: GENERIC_WRITE | READ_CONTROL | FILE_READ_ATTRIBUTES | DELETE,
            share: 0,
            disposition: FILE_CREATE,
            directory: false,
            security: Some(&file_security),
        },
    )?;
    let mut file = std::fs::File::from(handle);
    let write_result = (|| {
        ensure_ordinary_file(file.as_raw_handle())?;
        verify_private(file.as_raw_handle(), &user, false)?;
        // Every retained ancestor now contains the next retained directory, and
        // the last contains this exclusively held file. Recheck after creation:
        // a previously empty ancestor might have been retagged during traversal.
        // A nonempty ordinary directory cannot become a junction while those
        // children cannot be renamed/deleted. The final directory's private ACL
        // preserves that property after the exclusive writer closes.
        directories.verify_for_publication()?;
        let identity = file_identity(file.as_raw_handle())?;
        let original = retain_file_identity(file.as_raw_handle())?;
        file.write_all(bytes)?;
        Ok((identity, original))
    })();
    let (identity, original) = match write_result {
        Ok(result) => result,
        Err(error) => {
            // Delete the object already held, never a path another process could replace.
            let _ = mark_for_deletion(file.as_raw_handle());
            return Err(error);
        }
    };
    // Keep only the metadata handle: ordinary SDK file reads must work even when
    // they omit write/delete sharing.
    drop(file);
    Ok(PrivateFile {
        path: folder.join(name),
        name: name.to_os_string(),
        identity,
        _original: original,
        _directories: directories,
    })
}

/// A published file with a live identity and identity-checked, best-effort cleanup.
///
/// A metadata-only handle keeps the original object alive without blocking SDK
/// reads. Windows can refuse deletion while a client has the file open without
/// delete sharing; cleanup then leaves the file private. There is deliberately no
/// raw-path deletion fallback.
#[derive(Debug)]
pub struct PrivateFile {
    path: PathBuf,
    name: OsString,
    identity: FileIdentity,
    // Fields drop in declaration order after Drop::drop: close the original object
    // while the directory handles still prevent ancestor renames/deletion.
    _original: OwnedHandle,
    _directories: LockedDirectories,
}

impl PrivateFile {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for PrivateFile {
    fn drop(&mut self) {
        // The original metadata handle stays open through this destructor, so its
        // file ID cannot be reused. OPEN_REPARSE_POINT plus identity validation
        // prevents deleting a replacement entry or a link target.
        let Ok(Some(handle)) = open_existing_file(self._directories.last(), &self.name) else {
            return;
        };
        if ensure_ordinary_file(handle.as_raw_handle()).is_ok()
            && file_identity(handle.as_raw_handle()).is_ok_and(|id| id == self.identity)
        {
            let _ = mark_for_deletion(handle.as_raw_handle());
        }
    }
}

fn retain_file_identity(handle: HANDLE) -> io::Result<OwnedHandle> {
    // SAFETY: this is the live creation handle, not a path to reopen. Attribute-only
    // access is not subject to file sharing restrictions; share-all permits the
    // creation handle's write/delete access and later SDK opens. Keeping the object
    // alive prevents its file ID from being recycled after a rename or delete request.
    let retained = unsafe {
        ReOpenFile(
            handle,
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_FLAG_OPEN_REPARSE_POINT,
        )
    };
    owned_handle(retained)
}

#[derive(Debug, PartialEq, Eq)]
struct FileIdentity {
    volume: u64,
    id: [u8; 16],
}

fn file_identity(handle: HANDLE) -> io::Result<FileIdentity> {
    let mut info = MaybeUninit::<FILE_ID_INFO>::uninit();
    // SAFETY: FileIdInfo writes a FILE_ID_INFO of the supplied size on success.
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileIdInfo,
            info.as_mut_ptr().cast(),
            size_of::<FILE_ID_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let info = unsafe { info.assume_init() };
    Ok(FileIdentity {
        volume: info.VolumeSerialNumber,
        id: info.FileId.Identifier,
    })
}

struct LocalAllocation(*mut c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        // SAFETY: these buffers are returned by APIs documenting LocalFree ownership.
        unsafe { LocalFree(self.0) };
    }
}

struct SecurityDescriptor(LocalAllocation);

impl SecurityDescriptor {
    fn owner_only(sid: &str, directory: bool) -> io::Result<Self> {
        let inheritance = if directory { "OICI" } else { "" };
        let sddl = format!("O:{sid}D:P(A;{inheritance};FA;;;{sid})");
        Self::from_sddl(&sddl)
    }

    fn from_sddl(sddl: &str) -> io::Result<Self> {
        let wide: Vec<u16> = sddl.encode_utf16().chain([0]).collect();
        let mut descriptor = null_mut();
        // SAFETY: wide is NUL-terminated; descriptor receives a LocalAlloc-owned buffer.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(LocalAllocation(descriptor)))
    }

    #[cfg(test)]
    fn attributes(&self) -> windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
        use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
        SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0 .0,
            bInheritHandle: 0,
        }
    }
}

fn current_user_sid() -> io::Result<String> {
    let mut token = null_mut();
    // SAFETY: GetCurrentProcess is a pseudo-handle; OpenProcessToken initializes token.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = owned_handle(token)?;
    let mut required = 0;
    // SAFETY: a null, zero-length buffer asks the API for the required allocation size.
    unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            null_mut(),
            0,
            &mut required,
        )
    };
    let error = io::Error::last_os_error();
    if error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32)
        || required < size_of::<TOKEN_USER>() as u32
    {
        return Err(error);
    }
    // A word buffer gives TOKEN_USER pointer alignment, unlike a Vec<u8>.
    let words = (required as usize).div_ceil(size_of::<usize>());
    let mut buffer = vec![0usize; words];
    // SAFETY: buffer is aligned and at least required bytes long; the SID it receives
    // points into that buffer and is converted to owned text before the buffer drops.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            buffer.as_mut_ptr().cast(),
            required,
            &mut required,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    // SAFETY: GetTokenInformation returned a valid TOKEN_USER and embedded SID.
    unsafe { sid_string(user.User.Sid) }
}

/// `sid` must point to a valid SID for the duration of the call.
unsafe fn sid_string(sid: PSID) -> io::Result<String> {
    let mut text = null_mut();
    // SAFETY: the caller supplies a live SID; text receives a LocalAlloc-owned string.
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let allocation = LocalAllocation(text.cast());
    let mut length = 0;
    // SAFETY: a successful conversion returns a NUL-terminated UTF-16 string.
    unsafe {
        while *text.add(length) != 0 {
            length += 1;
        }
    }
    let text = unsafe { std::slice::from_raw_parts(text, length) };
    let result = String::from_utf16(text)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid Windows SID string"));
    drop(allocation);
    result
}

fn verify_private(handle: HANDLE, user: &str, directory: bool) -> io::Result<()> {
    let mut owner = null_mut();
    let mut acl: *mut ACL = null_mut();
    let mut descriptor = null_mut();
    // SAFETY: all output pointers are valid. Owner and ACL point into descriptor,
    // whose LocalAlloc-owned buffer stays live until all checks below finish.
    let error = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut acl,
            null_mut(),
            &mut descriptor,
        )
    };
    if error != 0 {
        return Err(io::Error::from_raw_os_error(error as i32));
    }
    let _allocation = LocalAllocation(descriptor);
    let mut control = 0;
    let mut revision = 0;
    // SAFETY: descriptor was returned successfully by GetSecurityInfo.
    if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if owner.is_null() || acl.is_null() || control & SE_DACL_PROTECTED == 0 {
        return Err(not_private());
    }
    // SAFETY: owner and ACL are live fields of the returned security descriptor.
    if unsafe { sid_string(owner)? } != user || unsafe { (*acl).AceCount } != 1 {
        return Err(not_private());
    }
    let mut ace = null_mut();
    // SAFETY: ACL has one entry; GetAce validates the index and returns its address.
    if unsafe { GetAce(acl, 0, &mut ace) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let header = unsafe { &*ace.cast::<ACE_HEADER>() };
    let expected_flags = if directory {
        (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8
    } else {
        0
    };
    if u32::from(header.AceType) != ACCESS_ALLOWED_ACE_TYPE
        || header.AceFlags != expected_flags
        || usize::from(header.AceSize) < size_of::<ACCESS_ALLOWED_ACE>()
    {
        return Err(not_private());
    }
    // SAFETY: the checked type is ACCESS_ALLOWED_ACE and its size covers these fields.
    let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
    let sid = std::ptr::addr_of!(allowed.SidStart).cast_mut().cast();
    if allowed.Mask != FILE_ALL_ACCESS || unsafe { sid_string(sid)? } != user {
        return Err(not_private());
    }
    Ok(())
}

fn not_private() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "the emulator file or port directory must have a protected owner-only Windows ACL; use a new port directory or explicitly secure the existing one",
    )
}

#[derive(Debug)]
struct LockedDirectories {
    handles: Vec<OwnedHandle>,
}

impl LockedDirectories {
    fn last(&self) -> &OwnedHandle {
        self.handles
            .last()
            .expect("the root handle is always retained")
    }

    fn verify_for_publication(&self) -> io::Result<()> {
        for handle in &self.handles {
            ensure_ordinary_directory(handle.as_raw_handle())?;
        }
        Ok(())
    }
}

fn lock_directories(
    folder: &Path,
    security: &SecurityDescriptor,
    user: &str,
) -> io::Result<LockedDirectories> {
    let mut components = folder.components();
    let Some(Component::Prefix(prefix)) = components.next() else {
        return Err(invalid_path());
    };
    if components.next() != Some(Component::RootDir) {
        return Err(invalid_path());
    }
    // Bootstrap only the volume/share root by name. All descendant operations use
    // one component relative to the preceding live handle, never a rebuilt path.
    let path = match prefix.kind() {
        Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) => {
            PathBuf::from(format!("\\\\?\\{}:\\", char::from(drive)))
        }
        Prefix::UNC(server, share) | Prefix::VerbatimUNC(server, share) => {
            let mut root = PathBuf::from("\\\\?\\UNC");
            root.push(server);
            root.push(share);
            root.push("");
            root
        }
        _ => return Err(invalid_path()),
    };
    let parts: Vec<_> = components.collect();
    if parts.is_empty() {
        return Err(invalid_path());
    }
    let mut directories = LockedDirectories {
        handles: vec![open_directory(&path, false)?],
    };
    #[cfg(test)]
    let mut path = path;
    for (index, component) in parts.iter().enumerate() {
        let Component::Normal(name) = component else {
            return Err(invalid_path());
        };
        let (handle, created) = open_relative(
            directories.last(),
            name,
            RelativeOpen {
                access: FILE_READ_ATTRIBUTES | READ_CONTROL,
                share: FILE_SHARE_READ,
                disposition: FILE_OPEN_IF,
                directory: true,
                security: Some(security),
            },
        )?;
        ensure_ordinary_directory(handle.as_raw_handle())?;
        if index + 1 == parts.len() || created {
            verify_private(handle.as_raw_handle(), user, true)?;
        }
        #[cfg(test)]
        {
            path.push(name);
            tests::after_directory_open(&path, &handle)?;
        }
        directories.handles.push(handle);
    }
    Ok(directories)
}

struct RelativeOpen<'a> {
    access: u32,
    share: u32,
    disposition: u32,
    directory: bool,
    security: Option<&'a SecurityDescriptor>,
}

/// The only descendant open/create primitive: a live parent and one ordinary name.
fn open_relative(
    parent: &OwnedHandle,
    name: &OsStr,
    options: RelativeOpen<'_>,
) -> io::Result<(OwnedHandle, bool)> {
    validate_component(name)?;
    let mut wide: Vec<u16> = name.encode_wide().collect();
    let byte_length = wide
        .len()
        .checked_mul(size_of::<u16>())
        .and_then(|length| u16::try_from(length).ok())
        .ok_or_else(invalid_path)?;
    let name = UNICODE_STRING {
        Length: byte_length,
        MaximumLength: byte_length,
        Buffer: wide.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.as_raw_handle(),
        ObjectName: &name,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: options
            .security
            .map_or(null(), |security| security.0 .0.cast()),
        SecurityQualityOfService: null(),
    };
    let mut status_block = IO_STATUS_BLOCK::default();
    let mut handle = null_mut();
    let kind = if options.directory {
        FILE_DIRECTORY_FILE
    } else {
        FILE_NON_DIRECTORY_FILE
    };
    // SAFETY: the parent, counted UTF-16 name, and optional security descriptor
    // remain live through this synchronous call. RootDirectory avoids resolving
    // ancestor paths. The single-component invariant makes OPEN_REPARSE_POINT
    // sufficient; callers inspect the returned entry before using or deleting it.
    // FILE_CREATE preserves create_new semantics; the ACL is applied atomically.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            options.access | SYNCHRONIZE,
            &attributes,
            &mut status_block,
            null(),
            FILE_ATTRIBUTE_NORMAL,
            options.share,
            options.disposition,
            FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT | kind,
            null(),
            0,
        )
    };
    // NT_SUCCESS accepts informational success codes as well as zero. This wrapper
    // always requests synchronous, non-alert I/O and never FILE_COMPLETE_IF_OPLOCKED,
    // so completion cannot be deferred (STATUS_PENDING) or returned before an
    // oplock break finishes. The status block and handle are complete on success.
    if status < 0 {
        // SAFETY: conversion accepts any NTSTATUS; this synchronous request has
        // completed and did not return an owning handle on failure.
        let error = unsafe { RtlNtStatusToDosError(status) };
        return Err(io::Error::from_raw_os_error(error as i32));
    }
    Ok((
        owned_handle(handle)?,
        status_block.Information == FILE_CREATED as usize,
    ))
}

// Used only to bootstrap the volume/share root (and inspect test fixtures).
fn open_directory(path: &Path, private: bool) -> io::Result<OwnedHandle> {
    let wide = wide_path(path)?;
    let access = FILE_READ_ATTRIBUTES | if private { READ_CONTROL } else { 0 };
    // SAFETY: the terminated path stays live through the call. The root is opened
    // as an entry, checked below, and retained without delete sharing.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            access,
            FILE_SHARE_READ,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    let handle = owned_handle(handle)?;
    ensure_ordinary_directory(handle.as_raw_handle())?;
    Ok(handle)
}

fn ensure_ordinary_directory(handle: HANDLE) -> io::Result<()> {
    let info = file_information(handle)?;
    if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "an emulator directory is not an ordinary directory (reparse points are refused)",
        ));
    }
    Ok(())
}

fn remove_existing_file(parent: &OwnedHandle, name: &OsStr) -> io::Result<()> {
    let Some(handle) = open_existing_file(parent, name)? else {
        return Ok(());
    };
    ensure_ordinary_file(handle.as_raw_handle())?;
    mark_for_deletion(handle.as_raw_handle())
}

fn open_existing_file(parent: &OwnedHandle, name: &OsStr) -> io::Result<Option<OwnedHandle>> {
    match open_relative(
        parent,
        name,
        RelativeOpen {
            access: DELETE | FILE_READ_ATTRIBUTES,
            share: 0,
            disposition: FILE_OPEN,
            directory: false,
            security: None,
        },
    ) {
        Ok((handle, _)) => Ok(Some(handle)),
        Err(error) if error.raw_os_error() == Some(ERROR_FILE_NOT_FOUND as i32) => Ok(None),
        Err(error) => Err(error),
    }
}

fn ensure_ordinary_file(handle: HANDLE) -> io::Result<()> {
    let info = file_information(handle)?;
    if info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
        || info.nNumberOfLinks != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "an emulator file is not an ordinary single-link file",
        ));
    }
    Ok(())
}

fn file_information(handle: HANDLE) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
    let mut info = MaybeUninit::uninit();
    // SAFETY: the live handle is readable for attributes; success fully initializes info.
    if unsafe { GetFileInformationByHandle(handle, info.as_mut_ptr()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { info.assume_init() })
}

fn mark_for_deletion(handle: HANDLE) -> io::Result<()> {
    let info = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: the handle has DELETE access and info matches FileDispositionInfo.
    if unsafe {
        SetFileInformationByHandle(
            handle,
            FileDispositionInfo,
            std::ptr::from_ref(&info).cast(),
            size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn owned_handle(handle: HANDLE) -> io::Result<OwnedHandle> {
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: this function is called only for newly returned owning Windows handles.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

fn wide_path(path: &Path) -> io::Result<Vec<u16>> {
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        return Err(invalid_path());
    }
    wide.push(0);
    Ok(wide)
}

fn validate_component(name: &OsStr) -> io::Result<()> {
    let wide: Vec<u16> = name.encode_wide().collect();
    if wide.is_empty()
        || wide
            .iter()
            .any(|c| matches!(*c, 0..=31 | 34 | 42 | 47 | 58 | 60 | 62 | 63 | 92 | 124))
        || matches!(wide.last(), Some(32 | 46))
    {
        return Err(invalid_path());
    }
    let text = name.to_string_lossy();
    let base = text.split('.').next().unwrap_or("").to_ascii_uppercase();
    let device = matches!(
        base.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$" | "CONIN$" | "CONOUT$"
    ) || ["COM", "LPT"].iter().any(|prefix| {
        base.strip_prefix(prefix).is_some_and(|suffix| {
            matches!(
                suffix,
                "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        })
    });
    if device {
        return Err(invalid_path());
    }
    Ok(())
}

fn invalid_path() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "invalid emulator file-system path",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use windows_sys::Win32::Foundation::ERROR_DIR_NOT_EMPTY;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateDirectoryW, FileDispositionInfoEx, FILE_DISPOSITION_FLAG_DELETE,
        FILE_DISPOSITION_FLAG_POSIX_SEMANTICS, FILE_DISPOSITION_INFO_EX, FILE_WRITE_ATTRIBUTES,
    };
    use windows_sys::Win32::System::Ioctl::{FSCTL_DELETE_REPARSE_POINT, FSCTL_SET_REPARSE_POINT};
    use windows_sys::Win32::System::SystemServices::IO_REPARSE_TAG_MOUNT_POINT;
    use windows_sys::Win32::System::IO::DeviceIoControl;

    type DirectoryHook = Box<dyn FnMut(&Path, &OwnedHandle) -> io::Result<()>>;
    thread_local! {
        static AFTER_OPEN: RefCell<Option<DirectoryHook>> = const { RefCell::new(None) };
    }

    // Per-thread and test-only: pause at the directory validation boundary.
    pub(super) fn after_directory_open(path: &Path, handle: &OwnedHandle) -> io::Result<()> {
        AFTER_OPEN.with(|hook| match hook.borrow_mut().as_mut() {
            Some(hook) => hook(path, handle),
            None => Ok(()),
        })
    }

    struct ScopedDirectoryHook;

    impl ScopedDirectoryHook {
        fn install(hook: impl FnMut(&Path, &OwnedHandle) -> io::Result<()> + 'static) -> Self {
            AFTER_OPEN.with(|slot| {
                let mut slot = slot.borrow_mut();
                assert!(slot.is_none());
                *slot = Some(Box::new(hook));
            });
            Self
        }
    }

    impl Drop for ScopedDirectoryHook {
        fn drop(&mut self) {
            AFTER_OPEN.with(|slot| *slot.borrow_mut() = None);
        }
    }

    fn junction_control(path: &Path, operation: u32, buffer: &[u8]) -> io::Result<()> {
        let wide = wide_path(path)?;
        // SAFETY: the fixture path is terminated; request only attribute access,
        // which is allowed even while the production directory denies write sharing.
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_WRITE_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        let handle = owned_handle(handle)?;
        let mut returned = 0;
        // SAFETY: the byte buffer has the documented mount-point reparse layout,
        // stays live for this synchronous call, and no output buffer is requested.
        if unsafe {
            DeviceIoControl(
                handle.as_raw_handle(),
                operation,
                buffer.as_ptr().cast(),
                u32::try_from(buffer.len()).unwrap(),
                null_mut(),
                0,
                &mut returned,
                null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn set_junction(path: &Path, target: &Path) -> io::Result<()> {
        let canonical = std::fs::canonicalize(target)?;
        let wide: Vec<_> = canonical.as_os_str().encode_wide().collect();
        if !wide.starts_with(&[92, 92, 63, 92]) {
            return Err(invalid_path());
        }
        // Convert the canonical Win32 extended path to its NT substitute name.
        let mut substitute = vec![92u16, 63, 63, 92];
        substitute.extend_from_slice(&wide[4..]);
        let name_bytes = u16::try_from(substitute.len() * 2).map_err(|_| invalid_path())?;
        let print_offset = name_bytes.checked_add(2).ok_or_else(invalid_path)?;
        let data_length = name_bytes.checked_add(12).ok_or_else(invalid_path)?;
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&IO_REPARSE_TAG_MOUNT_POINT.to_le_bytes());
        buffer.extend_from_slice(&data_length.to_le_bytes());
        buffer.extend_from_slice(&0u16.to_le_bytes()); // Reserved
        buffer.extend_from_slice(&0u16.to_le_bytes()); // SubstituteNameOffset
        buffer.extend_from_slice(&name_bytes.to_le_bytes());
        buffer.extend_from_slice(&print_offset.to_le_bytes());
        buffer.extend_from_slice(&0u16.to_le_bytes()); // Empty print name
        for unit in substitute.into_iter().chain([0, 0]) {
            buffer.extend_from_slice(&unit.to_le_bytes());
        }
        junction_control(path, FSCTL_SET_REPARSE_POINT, &buffer)
    }

    fn clear_junction(path: &Path) -> io::Result<()> {
        let mut buffer = Vec::from(IO_REPARSE_TAG_MOUNT_POINT.to_le_bytes());
        buffer.extend_from_slice(&[0; 4]); // ReparseDataLength and Reserved
        junction_control(path, FSCTL_DELETE_REPARSE_POINT, &buffer)
    }

    // Remove the tag before recursive fixture cleanup, including on test failure:
    // a relative create may have added a child to the original directory object.
    struct JunctionCleanup(PathBuf);

    impl Drop for JunctionCleanup {
        fn drop(&mut self) {
            let _ = clear_junction(&self.0);
        }
    }

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "aws-emulator-private-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            assert!(!path.exists(), "test directory must be fresh");
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_junction_added_after_ancestor_validation_cannot_redirect_creation_or_replacement() {
        for existing_target in [false, true] {
            let root = TestDirectory::new();
            let pivot = root.0.join("pivot");
            let outside = root.0.join("outside");
            std::fs::create_dir_all(&pivot).unwrap();
            std::fs::create_dir(&outside).unwrap();
            let target_guard = existing_target.then(|| {
                write_private_file(&outside.join("leaf"), "credentials", b"untouched").unwrap()
            });
            let _cleanup = JunctionCleanup(pivot.clone());
            let retagged = Rc::new(Cell::new(false));
            let observed = retagged.clone();
            let target = outside.clone();
            let _hook = ScopedDirectoryHook::install(move |path, _handle| {
                if path.file_name() == Some(OsStr::new("pivot")) {
                    set_junction(path, &target)?;
                    observed.set(true);
                }
                Ok(())
            });
            let result = write_private_file(&pivot.join("leaf"), "credentials", b"secret");
            assert!(
                retagged.get(),
                "the race fixture must successfully retag the held directory"
            );
            assert!(
                result.is_err(),
                "a redirected SDK pathname must never be published"
            );
            match &target_guard {
                Some(guard) => assert_eq!(std::fs::read(guard.path()).unwrap(), b"untouched"),
                None => assert!(!outside.join("leaf").exists()),
            }
            clear_junction(&pivot).unwrap();
            assert!(
                !pivot.join("leaf/credentials").exists(),
                "failed publication cleans up its own file"
            );
        }
    }

    #[test]
    fn an_existing_junction_is_refused_without_writing_into_its_target() {
        let root = TestDirectory::new();
        let pivot = root.0.join("pivot");
        let outside = root.0.join("outside");
        std::fs::create_dir_all(&pivot).unwrap();
        std::fs::create_dir(&outside).unwrap();
        let _cleanup = JunctionCleanup(pivot.clone());
        set_junction(&pivot, &outside).unwrap();
        assert!(write_private_file(&pivot.join("leaf"), "credentials", b"secret").is_err());
        assert!(std::fs::read_dir(&outside).unwrap().next().is_none());
    }

    #[test]
    fn a_published_nonempty_directory_cannot_be_retagged_as_a_junction() {
        let root = TestDirectory::new();
        let folder = root.0.join("9297");
        let guard = write_private_file(&folder, "credentials", b"secret").unwrap();
        let outside = root.0.join("outside");
        std::fs::create_dir(&outside).unwrap();
        let _cleanup = JunctionCleanup(folder.clone());
        let error = set_junction(&folder, &outside).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(ERROR_DIR_NOT_EMPTY as i32));
        assert_eq!(std::fs::read(guard.path()).unwrap(), b"secret");
        assert!(std::fs::read_dir(&outside).unwrap().next().is_none());
    }

    #[test]
    fn published_guards_allow_sdk_reads_other_files_and_nested_directories() {
        let root = TestDirectory::new();
        let folder = root.0.join("9297");
        let credentials = write_private_file(&folder, "credentials", b"secret").unwrap();
        let ca = write_private_file(&folder, "ca.pem", b"certificate").unwrap();
        let truststore =
            write_private_file(&folder, "truststore.p12", b"binary trust store").unwrap();
        let config = write_private_file(&folder, "config", b"[default]").unwrap();
        let nested = write_private_file(&folder.join("nested"), "config", b"nested").unwrap();
        assert_eq!(std::fs::read(credentials.path()).unwrap(), b"secret");
        assert_eq!(std::fs::read(ca.path()).unwrap(), b"certificate");
        assert_eq!(
            std::fs::read(truststore.path()).unwrap(),
            b"binary trust store"
        );
        assert_eq!(std::fs::read(config.path()).unwrap(), b"[default]");
        assert_eq!(std::fs::read(nested.path()).unwrap(), b"nested");
        let user = current_user_sid().unwrap();
        let directory = open_directory(&folder, true).unwrap();
        verify_private(directory.as_raw_handle(), &user, true).unwrap();
        use std::io::Read;
        use std::os::windows::fs::OpenOptionsExt;
        // Even a reader that grants no sharing must coexist with our attribute-only
        // handle. Retaining the creation handle's DELETE access would break this.
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(credentials.path())
            .unwrap();
        let mut contents = Vec::new();
        file.read_to_end(&mut contents).unwrap();
        assert_eq!(contents, b"secret");
        verify_private(file.as_raw_handle(), &user, false).unwrap();
        drop(file);
        let path = credentials.path().to_path_buf();
        drop(credentials);
        assert!(!path.exists());
        assert_eq!(std::fs::read(ca.path()).unwrap(), b"certificate");
        let paths =
            [ca.path(), truststore.path(), config.path(), nested.path()].map(Path::to_path_buf);
        drop((ca, truststore, config, nested));
        for path in paths {
            assert!(!path.exists());
        }
        let restarted = write_private_file(&folder, "credentials", b"new secret").unwrap();
        assert_eq!(std::fs::read(restarted.path()).unwrap(), b"new secret");
    }

    #[test]
    fn posix_deletion_keeps_the_original_identity_and_preserves_a_replacement() {
        let root = TestDirectory::new();
        let original = write_private_file(&root.0, "credentials", b"old").unwrap();
        let path = original.path().to_path_buf();
        let deletion = open_existing_file(original._directories.last(), OsStr::new("credentials"))
            .unwrap()
            .unwrap();
        let disposition = FILE_DISPOSITION_INFO_EX {
            Flags: FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
        };
        // Request POSIX deletion explicitly: DeleteFileW's observed name lifetime
        // must not be used as the identity-lifetime invariant. This native regression
        // requires FileDispositionInfoEx/POSIX support from the OS and filesystem;
        // production cleanup still uses the legacy FileDispositionInfo operation.
        // SAFETY: deletion owns a DELETE-capable handle; the structure and size match
        // FileDispositionInfoEx and remain live throughout the synchronous call.
        assert_ne!(
            unsafe {
                SetFileInformationByHandle(
                    deletion.as_raw_handle(),
                    FileDispositionInfoEx,
                    std::ptr::from_ref(&disposition).cast(),
                    size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
                )
            },
            0,
            "{}",
            io::Error::last_os_error()
        );
        // POSIX deletion releases the name when its deletion handle closes, while
        // the retained metadata handle keeps the original object and identity live.
        drop(deletion);
        assert_eq!(
            file_identity(original._original.as_raw_handle()).unwrap(),
            original.identity
        );
        let replacement = write_private_file(&root.0, "credentials", b"new").unwrap();
        assert_ne!(replacement.identity, original.identity);
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        assert_eq!(
            file_identity(original._original.as_raw_handle()).unwrap(),
            original.identity
        );
        drop(original);
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        assert_eq!(
            file_identity(replacement._original.as_raw_handle()).unwrap(),
            replacement.identity
        );
        drop(replacement);
        assert!(!path.exists());
    }

    #[test]
    fn refuses_an_existing_directory_with_inherited_permissions() {
        let root = TestDirectory::new();
        std::fs::create_dir_all(&root.0).unwrap();
        assert!(write_private_file(&root.0, "credentials", b"secret").is_err());
        assert!(!root.0.join("credentials").exists());
    }

    #[test]
    fn refuses_a_protected_directory_that_also_grants_everyone_access() {
        let root = TestDirectory::new();
        let setup = write_private_file(&root.0, "setup", b"public test data").unwrap();
        let user = current_user_sid().unwrap();
        let broad = SecurityDescriptor::from_sddl(&format!(
            "O:{user}D:P(A;OICI;FA;;;{user})(A;OICI;GR;;;WD)"
        ))
        .unwrap();
        let folder = root.0.join("broader-acl");
        let wide = wide_path(&folder).unwrap();
        // SAFETY: the descriptor and terminated path remain live through creation.
        assert_ne!(
            unsafe { CreateDirectoryW(wide.as_ptr(), &broad.attributes()) },
            0
        );
        assert_eq!(
            write_private_file(&folder, "credentials", b"secret")
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(!folder.join("credentials").exists());
        drop(setup);
    }

    #[test]
    fn published_guards_prevent_ancestor_replacement_until_cleanup() {
        let root = TestDirectory::new();
        let folder = root.0.join("9297");
        let guard = write_private_file(&folder, "credentials", b"secret").unwrap();
        assert!(std::fs::rename(&folder, root.0.join("moved")).is_err());
        let path = guard.path().to_path_buf();
        drop(guard);
        assert!(!path.exists());
        std::fs::rename(&folder, root.0.join("moved")).unwrap();
    }

    #[test]
    fn refuses_hard_links_without_modifying_their_target() {
        let root = TestDirectory::new();
        let original = write_private_file(&root.0, "original", b"untouched").unwrap();
        std::fs::hard_link(original.path(), root.0.join("credentials")).unwrap();
        assert!(write_private_file(&root.0, "credentials", b"secret").is_err());
        assert_eq!(std::fs::read(original.path()).unwrap(), b"untouched");
    }

    #[test]
    fn refuses_streams_devices_and_path_traversal() {
        let root = TestDirectory::new();
        for name in [
            "..",
            "../outside",
            "a\\b",
            "a:stream",
            "NUL",
            "CON.txt",
            "COM1",
            "LPT¹",
            "trailing.",
            "trailing ",
        ] {
            assert_eq!(
                write_private_file(&root.0, name, b"secret")
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidInput,
                "{name}"
            );
        }
        assert!(!root.0.exists());
    }

    #[test]
    fn refuses_symbolic_links_and_cleanup_never_follows_a_replacement_link() {
        let root = TestDirectory::new();
        let target = write_private_file(&root.0, "target", b"untouched").unwrap();
        let original = write_private_file(&root.0, "credentials", b"secret").unwrap();
        let path = original.path().to_path_buf();
        let retired = root.0.join("retired");
        std::fs::rename(&path, &retired).unwrap();
        if let Err(error) = std::os::windows::fs::symlink_file(target.path(), &path) {
            if error.raw_os_error() == Some(1314) {
                eprintln!(
                    "symlink test requires Windows Developer Mode or SeCreateSymbolicLinkPrivilege"
                );
                return;
            }
            panic!("create symlink: {error}");
        }
        assert!(write_private_file(&root.0, "credentials", b"replacement").is_err());
        drop(original);
        assert!(std::fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(std::fs::read(target.path()).unwrap(), b"untouched");
        assert_eq!(std::fs::read(&retired).unwrap(), b"secret");
        let alias = root.0.join("alias");
        std::os::windows::fs::symlink_dir(&root.0, &alias).unwrap();
        assert!(write_private_file(&alias, "new-file", b"secret").is_err());
        assert!(!root.0.join("new-file").exists());
        std::fs::remove_dir(alias).unwrap();
    }
}
