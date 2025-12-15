#ifndef COMMON_H
#define COMMON_H

#include "pin.H"
#include <fstream>
#include <map>
#include <string>

using namespace std;

/**
realistically,we dont expect more than this number of parameters
for a Windows API
 */
#define MAX_API_PARAM_COUNT 20

#define POLICY_JSON "ftbf_policy.json"
#define RULE_JSON "ftbf_rule.json"
#define APIS_JSON "apis.json"

/**
 * Logger class for thread-safe logging to per-thread log files.
 * Each thread gets its own log file named: pin_trace_PID-{pid}_TID-{tid}.log
 */
class Logger {
private:
  static map<NATIVE_TID, ofstream> log_handles;

  // Delete constructor to prevent instantiation
  Logger() = delete;

public:
  /**
   * Initialize the logger with the working directory path.
   * Should be called once at program startup before any logging.
   * 
   * @param working_directory The directory path where log files will be created
   */
  static void initialize(const char* working_directory);

  /**
   * Log a message to the current thread's log file.
   * Creates a new log file if this is the first call from this thread.
   *
   * @param message The message to log
   */
  static void log(const string &message);

  /**
   * Close all open log file handles.
   * Should be called during cleanup/shutdown.
   */
  static void close_all();
};

/**
 * Format a string using printf-style formatting.
 *
 * @param fmt_str Format string with printf-style placeholders
 * @param ... Variable arguments to be formatted
 * @return Formatted string
 */
string string_format(string fmt_str, ...);

/**
 * Extract directory path from executable path (argv[0]).
 * Handles both forward slashes (/) and backslashes (\).
 *
 * @param argv0 The argv[0] from main
 * @return Directory path, or "." if extraction fails
 */
string GetWorkingDirectory(const char* argv0);

extern "C" void *on_init(const char *policy_ptr, const char *rule_ptr,
                         const char *apis_ptr);
extern "C" void *on_exit(void *instance_ptr);
extern "C" void on_api_call(void *instance_ptr, const char *api_ptr,
                            const size_t *parameters);
extern "C" void on_call_or_jump(void *instance_ptr, size_t target_address);
extern "C" void on_api_return(void *instance_ptr, const char *api_ptr,
                              size_t return_value, size_t stack_ptr);

// Taint propagation functions
extern "C" void reg_to_reg(void *instance_ptr, uint32_t reg_dest,
                           uint32_t reg_source);
extern "C" void reg_to_mem(void *instance_ptr, size_t addr_dest,
                           uint32_t sz_dest, uint32_t reg_source);

// Regex-related functions
extern "C" bool is_regex_enabled(void *instance_ptr);
extern "C" void check_instr_regex(void *instance_ptr, CONTEXT* context, const char *instr_line);
extern "C" void mem_to_reg(void *instance_ptr, uint32_t reg_dest,
                           size_t addr_source, size_t sz_source);
extern "C" void mem_to_mem(void *instance_ptr, size_t addr_dest,
                           uint32_t sz_dest, size_t addr_source,
                           size_t sz_source);
extern "C" void immediate_to_reg(void *instance_ptr, uint32_t reg_dest,
                                 size_t immediate_source);
extern "C" void immediate_to_mem(void *instance_ptr, size_t addr_dest,
                                 size_t sz_dest, size_t immediate_source);

// Logging callback for Rust
extern "C" void dbi_log(const char *message);

#endif // COMMON_H
