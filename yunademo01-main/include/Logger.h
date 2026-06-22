#ifndef LOGGER_H
#define LOGGER_H

#include "Common.h"
#include "concurrentqueue.h"
#include <nlohmann/json.hpp>
#include <queue>
#include <atomic>
#include <mutex>
#include <thread>
#include <condition_variable>

extern thread_local std::string tl_log_buffer;
constexpr size_t TL_LOG_BUFFER_RESERVE = 512;

class Logger {
public:
    enum LogLevel { INFO, WARNING, ERROR, DEBUG };

    struct LogRecord {
        LogLevel level;
        std::string msg;
    };

    static std::string& prepareThreadLogBuffer();
    static void logFromBufferAndMove(std::string&& preparedBuffer, LogLevel level = INFO);
    static void setLevel(LogLevel level);
    static void log(const std::string& message, LogLevel level = INFO);
    static void startAsyncLogger();
    static void shutdownAsyncLogger();
    static void rotateLogs();
    
    static LogLevel currentLevel;
    static nlohmann::json getQueueMetrics();

private:
    static moodycamel::ConcurrentQueue<LogRecord> lfLogQueue;
    static std::queue<LogRecord> fallbackLogQueue;
    static std::mutex logMutex;
    static std::condition_variable logCV;
    static std::atomic<bool> writerRunning;
    static std::thread writerThread;

    static std::atomic<size_t> queuedCount;
    static std::atomic<size_t> droppedLogs;
    constexpr static size_t MAX_LOG_QUEUE_SIZE = 65536;

    static std::atomic<long long> cachedTsMs;
    static std::string cachedTsStr;
    static std::mutex cachedTsMutex;
    constexpr static int TIMESTAMP_CACHE_MS = 200;

    static std::string getLogFilePath();
    static std::string getTimestamp();
    static std::string encryptLog(const std::string& message);
    static std::string levelToString(LogLevel level);
    static std::string getCachedTimestamp();

    static constexpr size_t LOGGER_BATCH_SIZE = 128;
    static constexpr size_t LOGGER_FLUSH_INTERVAL_MS = 50;
    static void writerLoop();
};

#endif // LOGGER_H
