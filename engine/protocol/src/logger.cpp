#include "engine/logger.hpp"
#include <iomanip>

namespace engine {

Logger& Logger::instance() {
    static Logger inst;
    return inst;
}

void Logger::set_level(LogLevel level) {
    std::lock_guard<std::mutex> lock(log_mutex_);
    current_level_ = level;
}

LogLevel Logger::get_level() const {
    return current_level_;
}

void Logger::log(LogLevel level, const std::string& subsystem, const std::string& message) {
    if (static_cast<int>(level) < static_cast<int>(current_level_)) {
        return;
    }

    auto now = std::chrono::system_clock::now();
    auto now_c = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;

    std::tm time_info{};
#if defined(_WIN32) || defined(_WIN64)
    gmtime_s(&time_info, &now_c);
#else
    gmtime_r(&now_c, &time_info);
#endif

    std::ostringstream ss;
    ss << "{\"timestamp\":\""
       << std::put_time(&time_info, "%Y-%m-%dT%H:%M:%S")
       << '.' << std::setfill('0') << std::setw(3) << ms.count() << "Z\""
       << ",\"level\":\"" << to_string(level) << "\""
       << ",\"subsystem\":\"" << subsystem << "\""
       << ",\"message\":\"" << message << "\"}";

    std::lock_guard<std::mutex> lock(log_mutex_);
    std::cout << ss.str() << std::endl;
}

} // namespace engine
