#pragma once

#include <string>
#include <fstream>
#include <mutex>
#include <sstream>
#include <iostream>
#include <chrono>
#include <iomanip>

enum class LogLevel
{
    DEBUG,
    INFO,
    WARN,
    ERROR
};

class Logger
{
public:
    /// Thread-safe Meyer's singleton.
    static Logger &instance();

    /// Write a log entry at the given level.
    void log(LogLevel level, const std::string &module, const std::string &message);

    /// Set the minimum level that will be emitted.
    void setLevel(LogLevel min_level);

    /// Open (or re-open) a file for log output in addition to stdout.
    void enableFileOutput(const std::string &path);

private:
    Logger() = default;
    ~Logger()
    {
        if (file_out_.is_open())
            file_out_.close();
    }

    Logger(const Logger &) = delete;
    Logger &operator=(const Logger &) = delete;

    LogLevel min_level_{LogLevel::DEBUG};
    std::ofstream file_out_;
    std::mutex mutex_;
};