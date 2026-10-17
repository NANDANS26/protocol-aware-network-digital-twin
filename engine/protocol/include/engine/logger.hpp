#pragma once

#include <string>
#include <iostream>
#include <chrono>
#include <mutex>
#include <sstream>

namespace engine {

enum class LogLevel {
    Debug,
    Info,
    Warning,
    Error
};

inline const char* to_string(LogLevel level) {
    switch (level) {
        case LogLevel::Debug: return "DEBUG";
        case LogLevel::Info: return "INFO";
        case LogLevel::Warning: return "WARNING";
        case LogLevel::Error: return "ERROR";
        default: return "UNKNOWN";
    }
}

inline LogLevel parse_log_level(const std::string& level_str) {
    if (level_str == "DEBUG" || level_str == "debug") return LogLevel::Debug;
    if (level_str == "WARNING" || level_str == "warning") return LogLevel::Warning;
    if (level_str == "ERROR" || level_str == "error") return LogLevel::Error;
    return LogLevel::Info;
}

class Logger {
public:
    static Logger& instance();

    void set_level(LogLevel level);
    [[nodiscard]] LogLevel get_level() const;

    void log(LogLevel level, const std::string& subsystem, const std::string& message);

private:
    Logger() = default;
    LogLevel current_level_{LogLevel::Info};
    std::mutex log_mutex_;
};

#define LOG_DEBUG(subsystem, msg) engine::Logger::instance().log(engine::LogLevel::Debug, subsystem, msg)
#define LOG_INFO(subsystem, msg) engine::Logger::instance().log(engine::LogLevel::Info, subsystem, msg)
#define LOG_WARN(subsystem, msg) engine::Logger::instance().log(engine::LogLevel::Warning, subsystem, msg)
#define LOG_ERROR(subsystem, msg) engine::Logger::instance().log(engine::LogLevel::Error, subsystem, msg)

} // namespace engine
