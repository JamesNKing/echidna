use crate::agent::AgentTask;
use serde_json::json;

/// Exit the agent gracefully
/// * `task` - Task information from Mythic
/// * `exit_agent` - Mutable reference to the exit flag
pub fn exit_agent(task: &AgentTask, exit_agent: &mut bool) -> serde_json::Value {
    *exit_agent = true;

    json!({
        "task_id": task.id,
        "status": "success",
        "user_output": "Agent shutting down gracefully. Cleaning up rootkit techniques...",
        "completed": true,
    })
}
