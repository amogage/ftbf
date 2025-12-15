use core::ffi::c_char;
use log::{Metadata, Record};

unsafe extern "C" {
    fn dbi_log(message: *const c_char);
}

pub struct CppLogger;

impl log::Log for CppLogger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        // Enable all log levels
        true
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            // Format the log message with level, file, line, and message
            let formatted = if let (Some(file), Some(line)) = (record.file(), record.line()) {
                format!(
                    "[{}] {}:{} - {}\n",
                    record.level(),
                    file,
                    line,
                    record.args()
                )
            } else {
                format!("[{}] {}\n", record.level(), record.args())
            };

            // Convert to C string and call the C++ logging function
            let c_string = alloc::ffi::CString::new(formatted);
            if let Ok(c_str) = c_string {
                unsafe {
                    dbi_log(c_str.as_ptr());
                }
            }
        }
    }

    fn flush(&self) {
        // The C++ logger flushes immediately, so nothing to do here
    }
}

static LOGGER: CppLogger = CppLogger;

pub fn init() -> Result<(), log::SetLoggerError> {
    log::set_logger(&LOGGER)?;
    log::set_max_level(log::LevelFilter::Trace);
    Ok(())
}

