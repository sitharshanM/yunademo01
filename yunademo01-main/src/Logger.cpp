#include "Logger.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <ctime>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

thread_local std::string tl_log_buffer;

Logger::LogLevel Logger::currentLevel = Logger::INFO;
moodycamel::ConcurrentQueue<Logger::LogRecord> Logger::lfLogQueue;
std::queue<Logger::LogRecord> Logger::fallbackLogQueue;
std::mutex Logger::logMutex;
std::condition_variable Logger::logCV;
std::atomic<bool> Logger::writerRunning{false};
std::thread Logger::writerThread;
std::atomic<size_t> Logger::queuedCount{0};
std::atomic<size_t> Logger::droppedLogs{0};
std::atomic<long long> Logger::cachedTsMs{0};
std::string Logger::cachedTsStr = "";
std::mutex Logger::cachedTsMutex;

std::string& Logger::prepareThreadLogBuffer() {
    if (tl_log_buffer.capacity() < TL_LOG_BUFFER_RESERVE) {
        tl_log_buffer.reserve(TL_LOG_BUFFER_RESERVE);
    }
    tl_log_buffer.clear();
    return tl_log_buffer;
}

void Logger::logFromBufferAndMove(std::string&& preparedBuffer, LogLevel level) {
    Logger::log(std::move(preparedBuffer), level);
}

void Logger::setLevel(LogLevel level) {
    currentLevel = level;
    log("Logging level set to " + std::to_string(level), INFO);
}

void Logger::log(const std::string& message, LogLevel level) {
    if (level < currentLevel) return;
    
    size_t current = queuedCount.load(std::memory_order_relaxed);
    if (current >= MAX_LOG_QUEUE_SIZE) {
        droppedLogs.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    LogRecord rec{ level, message };
    bool enqueued = lfLogQueue.try_enqueue(rec);

    if (!enqueued) {
        std::lock_guard<std::mutex> lock(logMutex);
        fallbackLogQueue.push(std::move(rec));
    }
    queuedCount.fetch_add(1, std::memory_order_relaxed);
    logCV.notify_one();
}

void Logger::startAsyncLogger() {
    if (writerRunning.load()) {
        return;
    }
    writerRunning = true;
    writerThread = std::thread(writerLoop);
}

void Logger::shutdownAsyncLogger() {
    writerRunning = false;
    logCV.notify_all();
    if (writerThread.joinable()) {
        writerThread.join();
    }
}

void Logger::rotateLogs() {
    std::string path = getLogFilePath();
    struct stat st;
    if (stat(path.c_str(), &st) == 0 && st.st_size > LOG_ROTATION_SIZE) {
        std::string oldPath = path + ".old";
        if (rename(path.c_str(), oldPath.c_str()) == 0) {
            std::cerr << "[Logger] Log file rotated successfully." << std::endl;
        } else {
            std::cerr << "[Logger] Failed to rotate log file." << std::endl;
        }
    }
}

nlohmann::json Logger::getQueueMetrics() {
    nlohmann::json j;
    j["queued"] = queuedCount.load();
    j["dropped"] = droppedLogs.load();
    j["max_capacity"] = MAX_LOG_QUEUE_SIZE;
    return j;
}

std::string Logger::getLogFilePath() {
    char* home = getenv("HOME");
    if (!home) {
        std::cerr << "Error: HOME environment variable not set." << std::endl;
        exit(1);
    }
    std::string logDir = std::string(home) + "/FirewallManagerLogs";
    if (mkdir(logDir.c_str(), 0755) != 0 && errno != EEXIST) {
        std::cerr << "Error: Failed to create log directory " << logDir << ": " << strerror(errno) << std::endl;
        exit(1);
    }
    return logDir + "/firewall_manager.log";
}

std::string Logger::getTimestamp() {
    auto now = std::chrono::system_clock::now();
    time_t tt = std::chrono::system_clock::to_time_t(now);
    tm local_tm;
    if (localtime_r(&tt, &local_tm) == nullptr) {
        return "TIME_ERROR";
    }
    char buffer[80];
    strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%S", &local_tm);
    return std::string(buffer);
}

std::string Logger::encryptLog(const std::string& message) {
    return "[ENCRYPTED]" + message; // Placeholder
}

std::string Logger::levelToString(LogLevel level) {
    switch (level) {
        case INFO: return "INFO";
        case WARNING: return "WARNING";
        case ERROR: return "ERROR";
        case DEBUG: return "DEBUG";
        default: return "UNKNOWN";
    }
}

std::string Logger::getCachedTimestamp() {
    using namespace std::chrono;
    long long nowMs = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
    long long last = cachedTsMs.load(std::memory_order_relaxed);

    if (nowMs - last < TIMESTAMP_CACHE_MS && !cachedTsStr.empty()) {
        return cachedTsStr;
    }

    std::lock_guard<std::mutex> lock(cachedTsMutex);
    last = cachedTsMs.load(std::memory_order_relaxed);
    if (nowMs - last < TIMESTAMP_CACHE_MS && !cachedTsStr.empty()) {
        return cachedTsStr;
    }

    std::time_t tt = std::time(nullptr);
    std::tm tm_buf;
    localtime_r(&tt, &tm_buf);
    char buf[64];
    size_t n = strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tm_buf);
    (void)n;
    int ms_part = (int)(nowMs % 1000);
    char finalBuf[80];
    snprintf(finalBuf, sizeof(finalBuf), "%s.%03d", buf, ms_part);

    cachedTsStr = std::string(finalBuf, strlen(finalBuf));
    cachedTsMs.store(nowMs, std::memory_order_relaxed);
    return cachedTsStr;
}

void Logger::writerLoop() {
    FILE* fp = fopen(getLogFilePath().c_str(), "a");
    if (!fp) {
        std::cerr << "[Logger] Failed to open log file." << std::endl;
        return;
    }

    static thread_local std::vector<char> logFileBuffer;
    logFileBuffer.resize(64 * 1024);
    setvbuf(fp, logFileBuffer.data(), _IOFBF, logFileBuffer.size());

    while (true) {
        std::unique_lock<std::mutex> lock(logMutex);
        logCV.wait(lock, [] {
            return Logger::queuedCount.load(std::memory_order_relaxed) > 0 || !writerRunning.load();
        });

        if (!writerRunning.load() && Logger::queuedCount.load(std::memory_order_relaxed) == 0) {
            break;
        }

        std::string batchBuffer;
        batchBuffer.reserve(8192);
        size_t collected = 0;
        LogRecord rec;

        auto appendRecord = [&](const LogRecord& record) {
            batchBuffer.append(getCachedTimestamp());
            batchBuffer.append(" [");
            batchBuffer.append(levelToString(record.level));
            batchBuffer.append("] ");
            batchBuffer.append(encryptLog(record.msg));
            batchBuffer.push_back('\n');
        };

        lock.unlock();

        while (collected < LOGGER_BATCH_SIZE && lfLogQueue.try_dequeue(rec)) {
            appendRecord(rec);
            collected++;
            queuedCount.fetch_sub(1, std::memory_order_relaxed);
        }

        {
            std::lock_guard<std::mutex> fallbackLock(logMutex);
            while (collected < LOGGER_BATCH_SIZE && !fallbackLogQueue.empty()) {
                rec = std::move(fallbackLogQueue.front());
                fallbackLogQueue.pop();
                appendRecord(rec);
                collected++;
                queuedCount.fetch_sub(1, std::memory_order_relaxed);
            }
        }

        if (!batchBuffer.empty()) {
            fwrite(batchBuffer.data(), 1, batchBuffer.size(), fp);
        }

        static auto lastFlush = std::chrono::steady_clock::now();
        auto now = std::chrono::steady_clock::now();
        if (now - lastFlush >= std::chrono::milliseconds(LOGGER_FLUSH_INTERVAL_MS) || !writerRunning.load()) {
            fflush(fp);
            lastFlush = now;
        }
    }

    fclose(fp);
}
