#include "common.h"
#include <cstdarg>
#include <memory>
#include <ctime>
#include <sstream>

// Static member initialization
map<NATIVE_TID, ofstream> Logger::log_handles;

// Buffer size for faster logging
constexpr size_t LOG_BUFFER_SIZE = 8192;

// Configuration constants
string LOG_PATH = ".";  // Will be set to actual working directory at initialization
const string LOG_TEMPLATE_NAME = "%s\\pin_trace_PID-%d_TID-%d.log";

// String formatting utility using variadic arguments
// Note: C++20 std::format or fmt library would be preferred, but not available here
// Adapted from https://stackoverflow.com/a/8098080/2533467
string string_format(string fmt_str, ...) {
    constexpr int INITIAL_SIZE_MULTIPLIER = 2;
    constexpr int MAX_ITERATIONS = 10; // Safety limit to prevent infinite loops
    
    int final_n;
    int n = static_cast<int>(fmt_str.size()) * INITIAL_SIZE_MULTIPLIER;
    unique_ptr<char[]> formatted;
    va_list ap;
    int iterations = 0;
    
    while (iterations < MAX_ITERATIONS) {
        formatted.reset(new char[n]);
        
        va_start(ap, fmt_str);
        final_n = vsnprintf(&formatted[0], n, fmt_str.c_str(), ap);
        va_end(ap);
        
        // Check if the buffer was large enough
        if (final_n >= 0 && final_n < n) {
            // Success: the string fit in the buffer
            // Use constructor with known size for efficiency
            return string(formatted.get(), final_n);
        }
        
        // Calculate new buffer size
        if (final_n >= 0) {
            // We know exactly how much space we need
            n = final_n + 1;
        } else {
            // Error or buffer too small, double the size
            n *= 2;
        }
        
        ++iterations;
    }
    
    return string(formatted.get());
}

// Get current timestamp in a readable format
static string get_timestamp() {
    time_t now = time(nullptr);
    struct tm* timeinfo = localtime(&now);
    
    if (!timeinfo) {
        return "[timestamp unavailable]";
    }
    
    char buffer[32];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeinfo);
    return string(buffer);
}

string GetWorkingDirectory(const char* argv0) {
    if (argv0 == nullptr) {
        return ".";
    }
    
    string exe_path(argv0);
    size_t last_sep = exe_path.find_last_of("/\\");
    
    if (last_sep != string::npos) {
        return exe_path.substr(0, last_sep);
    }
    
    return ".";
}

void Logger::initialize(const char* working_directory) {
    static bool initialized = false;
    if (!initialized) {
        if (working_directory != nullptr && working_directory[0] != '\0') {
            LOG_PATH = string(working_directory);
        }
        // If nullptr or empty string, LOG_PATH remains as "." (current directory)
        
        initialized = true;
    }
}

void Logger::log(const string& message) {
    NATIVE_PID pid;
    NATIVE_TID tid;
    
    OS_GetPid(&pid);
    OS_GetTid(&tid);
    
    // Create log file handle for this thread if it doesn't exist
    if (log_handles.find(tid) == log_handles.end()) {
        // Pre-allocate string to avoid reallocation
        string log_name;
        log_name.reserve(256);
        
        // Use stringstream for more efficient string building
        std::ostringstream oss;
        oss << LOG_PATH << "\\pin_trace_PID-" << pid << "_TID-" << tid << ".log";
        log_name = oss.str();
        
        ofstream log_handle(log_name.c_str(), ios_base::out | ios_base::app);
        
        // Note: We don't set a custom buffer here to avoid thread-safety issues.
        // Each thread's ofstream uses its own internal buffer by default.
        
        log_handles[tid] = std::move(log_handle);
    }
    
    ofstream& log_handle = log_handles[tid];
    
    // Verify the log file is open before writing
    if (!log_handle.is_open()) {
        return;
    }
    
    // Build log entry more efficiently
    log_handle << '[' << get_timestamp() << "] " << message;
    // Only flush periodically for better performance
    if (message.back() == '\n') {
        log_handle.flush();
    }
}

void Logger::close_all() {
    for (auto& entry : log_handles) {
        if (entry.second.is_open()) {
            entry.second.close();
        }
    }
    log_handles.clear();
}
