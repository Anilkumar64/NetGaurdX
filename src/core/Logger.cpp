#include "core/Logger.h"

Logger &Logger::instance() {
  static Logger inst;
  return inst;
}

void Logger::setLevel(LogLevel min_level) {
  std::lock_guard<std::mutex> lk(mutex_);
  min_level_ = min_level;
}

void Logger::enableFileOutput(const std::string &path) {
  std::lock_guard<std::mutex> lk(mutex_);
  if (file_out_.is_open())
    file_out_.close();
  file_out_.open(path, std::ios::out | std::ios::app);
}

void Logger::log(LogLevel level, const std::string &module,
                 const std::string &message) {
  std::lock_guard<std::mutex> lk(mutex_);
  if (level < min_level_)
    return;

  // Build timestamp: HH:MM:SS.mmm
  auto now = std::chrono::system_clock::now();
  auto now_tt = std::chrono::system_clock::to_time_t(now);
  auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    now.time_since_epoch()) %
                1000;

  std::ostringstream ts;
  ts << std::put_time(std::localtime(&now_tt), "%H:%M:%S") << '.'
     << std::setfill('0') << std::setw(3) << now_ms.count();

  const char *lvl_str = "DEBUG";
  switch (level) {
  case LogLevel::DEBUG:
    lvl_str = "DEBUG";
    break;
  case LogLevel::INFO:
    lvl_str = "INFO";
    break;
  case LogLevel::WARN:
    lvl_str = "WARN";
    break;
  case LogLevel::ERROR:
    lvl_str = "ERROR";
    break;
  }

  std::string line =
      "[" + ts.str() + "][" + lvl_str + "][" + module + "] " + message + "\n";

  std::cout << line;
  if (level >= LogLevel::WARN)
    std::cout.flush();

  if (file_out_.is_open()) {
    file_out_ << line;
    if (level >= LogLevel::WARN)
      file_out_.flush();
  }
}