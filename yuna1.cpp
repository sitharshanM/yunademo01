```cpp
#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <map>
#include <unordered_map>
#include <set>
#include <chrono>
#include <thread>
#include <mutex>
#include <random>
#include <cmath>
// [AsyncLogger Patch #1] Added stdio header for batched fwrite usage
#include <cstdio>
#include <ctime>
#include <time.h>
#include <cstdlib>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <curl/curl.h>
#include <pcap/pcap.h>
#include <nlohmann/json.hpp>
#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <future>
#include <queue>
#include <regex>
#include <csignal>
#include <limits>
#include <readline/readline.h>
#include <readline/history.h>
// [AsyncLogger Patch #5] Use moodycamel concurrent queue for lock-free producers
#include "concurrentqueue.h"   // moodycamel::ConcurrentQueue (header-only)
// [AsyncLogger Patch #5] Dependency: ensure third_party/moodycamel is on the include path
#include <cstring>
// [AsyncLogger Patch #7] Thread-local buffers reduce allocations when logging in tight loops (packet processing).
// [AsyncLogger Patch #7] Thread-local buffer to avoid heap allocations in hot path
thread_local std::string tl_log_buffer;
constexpr size_t TL_LOG_BUFFER_RESERVE = 512; // default reserve per thread
#include <QtWidgets/QApplication>
#include <QtWidgets/QMainWindow>
#include <QtWidgets/QTabWidget>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QLabel>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QTextEdit>
#include <QtWidgets/QFileDialog>
using json = nlohmann::json;
using namespace std;
// Struct definitions (moved to top to fix compilation errors)
struct BlockedDomain {
    string domain;
    string category; // e.g., "sports", "news"
    set<string> resolvedIPs; // IPs resolved from the domain
};
struct NetworkFeatures {
    double packetRate;
    double packetSize;
    double connectionDuration;
    double portNumber;
};
struct ConnectionState {
    string state;
    string sourceIP;
    string destIP;
    string sourcePort;
    string destPort;
    chrono::system_clock::time_point lastUpdate;
    int packetCount;
    long long totalBytes;
    bool wasBlocked;
};
struct NetworkTrafficData {
    string sourceIP;
    string destIP;
    int packetCount;
    long long bytesTransferred;
};
struct FirewallRule {
    string action;
    string direction;
    string source;
    string destination;
    string protocol;
};

// NEW ASYNC LOGGER STRUCT
struct LogRecord {
    Logger::LogLevel level;
    std::string msg;
};
// Constants
#define TIMEOUT_SECONDS 3600
#define MAX_TRAINING_SAMPLES 1000
#define LEARNING_RATE 0.01
#define EPOCHS 500
#define THREAT_THRESHOLD 0.7
#define PACKET_RATE_THRESHOLD 100.0
#define CONNECTION_THRESHOLD 50
#define AVERAGE_PACKET_SIZE 512
#define PACKET_SIZE_MULTIPLIER 5
#define MAINTENANCE_INTERVAL_MS 3600000
#define THREAT_CHECK_INTERVAL_MS 10000
#define LOG_ROTATION_SIZE 10485760
#define DROPOUT_RATE 0.2
#define BATCH_SIZE 32
#define MODEL_FILE "neural_model.json"
#define CONFIG_FILE "yuna_config.json"
#define BLOCKED_IPS_FILE "blocked_ips.json"
#define BLOCKED_DOMAINS_FILE "blocked_domains.json"
#define THREAT_INTEL_API "https://api.threatintel.example.com/query"
// Forward declarations
class NeuralNetwork;
class FirewallManager;
class PacketSniffer;
class ThreatIntelligenceIntegrator;
string getHelpInformation(const string& category = "");
// Global variables
mutex globalMutex;
atomic<bool> running(true);
set<string>* blockedIPsPtr = nullptr; // Pointer to blockedIPs for autocompletion
map<string, BlockedDomain>* blockedDomainsPtr = nullptr; // Pointer to blockedDomains for autocompletion
// Signal handler
void signalHandler(int signum) {
    cout << "Interrupt signal (" << signum << ") received. Shutting down gracefully..." << endl;
    running = false;
}
// Logger class
class Logger {
public:
    // [AsyncLogger Patch #7] Thread-local buffers reduce allocations; see prepareThreadLogBuffer() usage notes.
    // [AsyncLogger Patch #6] Logger now has a bounded queue with drop policy to prevent RAM overuse under high log rates.
    enum LogLevel { INFO, WARNING, ERROR, DEBUG };
    // [AsyncLogger Patch #7] Prepare thread-local buffer and return a reference for building messages
    static std::string& prepareThreadLogBuffer() {
        if (tl_log_buffer.capacity() < TL_LOG_BUFFER_RESERVE) {
            tl_log_buffer.reserve(TL_LOG_BUFFER_RESERVE);
        }
        tl_log_buffer.clear();
        return tl_log_buffer;
    }
    // [AsyncLogger Patch #7] Convenience overload that forwards moved buffers into Logger::log
    static void logFromBufferAndMove(std::string&& preparedBuffer, LogLevel level = INFO) {
        Logger::log(std::move(preparedBuffer), level);
    }
    static void setLevel(LogLevel level) {
        currentLevel = level;
        log("Logging level set to " + to_string(level), INFO);
    }
    /* OLD SYNC LOGGER - DISABLED
    static void log(const string &message, LogLevel level = INFO) {
        if (level < currentLevel) return;
        string levelStr;
        switch (level) {
            case INFO: levelStr = "INFO"; break;
            case WARNING: levelStr = "WARNING"; break;
            case ERROR: levelStr = "ERROR"; break;
            case DEBUG: levelStr = "DEBUG"; break;
            default: levelStr = "UNKNOWN"; break;
        }
        string encryptedMsg = encryptLog(message);
        string entry = getTimestamp() + " [" + levelStr + "] " + encryptedMsg + "\n";
        lock_guard<mutex> lock(globalMutex);
        ofstream logFile(getLogFilePath(), ios::app);
        if (logFile.is_open()) {
            logFile << entry;
            logFile.close();
        } else {
            cerr << "Error: Failed to open log file." << endl;
        }
    }
    */
    // [AsyncLogger Patch #7] Usage: auto& buf = Logger::prepareThreadLogBuffer(); buf.append(...); Logger::log(std::move(buf), level);
    static void log(const std::string& message, LogLevel level = INFO) {
        if (level < currentLevel) return;
        // [AsyncLogger Patch #6] Enforce bounded queue size
        size_t current = queuedCount.load(std::memory_order_relaxed);
        if (current >= MAX_LOG_QUEUE_SIZE) {
            if (level == DEBUG) {
                droppedLogs.fetch_add(1, std::memory_order_relaxed);
                return;
            }
            droppedLogs.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        // [AsyncLogger Patch #4] Only enqueue raw (unencrypted) message in hot path
        // [AsyncLogger Patch #5] Try lock-free enqueue first; fallback to locked queue if necessary
        LogRecord rec{ level, message };
        bool enqueued = lfLogQueue.try_enqueue(rec);

        if (!enqueued) {
            // [AsyncLogger Patch #5] Fallback path: use locked queue to guarantee delivery
            std::lock_guard<std::mutex> lock(logMutex);
            fallbackLogQueue.push(std::move(rec));
        }
        // [AsyncLogger Patch #6] Increment queuedCount after successful enqueue
        queuedCount.fetch_add(1, std::memory_order_relaxed);

        logCV.notify_one();
    }
    static void startAsyncLogger() {
        if (writerRunning.load()) {
            return;
        }
        writerRunning = true;
        writerThread = std::thread(writerLoop);
    }
    static void shutdownAsyncLogger() {
        writerRunning = false;
        logCV.notify_all();
        if (writerThread.joinable()) {
            writerThread.join();
        }
    }
    static void rotateLogs() {
        string path = getLogFilePath();
        struct stat st;
        if (stat(path.c_str(), &st) == 0 && st.st_size > LOG_ROTATION_SIZE) {
            string oldPath = path + ".old";
            if (rename(path.c_str(), oldPath.c_str()) == 0) {
                // [AsyncLogger Patch #4] Avoid recursive log calls during rotation
                std::cerr << "[Logger] Log file rotated successfully." << std::endl;
            } else {
                std::cerr << "[Logger] Failed to rotate log file." << std::endl;
            }
        }
    }
private:
    static LogLevel currentLevel;
    // NEW: Async logging internals
    // [AsyncLogger Patch #5] Lock-free producer queue for fast non-blocking enqueues
    static moodycamel::ConcurrentQueue<LogRecord> lfLogQueue;
    // [AsyncLogger Patch #5] Fallback locked queue (rarely used if lock-free fails)
    static std::queue<LogRecord> fallbackLogQueue;
    static std::mutex logMutex;
    static std::condition_variable logCV;
    static std::atomic<bool> writerRunning;
    static std::thread writerThread;
    // [AsyncLogger Patch #6] Bounded queue counters
    static std::atomic<size_t> queuedCount;        // number of queued log messages
    static std::atomic<size_t> droppedLogs;        // number of dropped log messages
    // [AsyncLogger Patch #6] Queue capacity limit
    constexpr static size_t MAX_LOG_QUEUE_SIZE = 65536;   // 64K entries
    // [AsyncLogger Patch #3] Cached timestamp variables to reduce strftime calls
    static std::atomic<long long> cachedTsMs;        // epoch ms of cached string
    static std::string cachedTsStr;                  // formatted timestamp string
    static std::mutex cachedTsMutex;                 // protects cachedTsStr update
    constexpr static int TIMESTAMP_CACHE_MS = 200;   // cache duration in milliseconds
    static string getLogFilePath() {
        char* home = getenv("HOME");
        if (!home) {
            cerr << "Error: HOME environment variable not set." << endl;
            exit(1);
        }
        string logDir = string(home) + "/FirewallManagerLogs";
        if (mkdir(logDir.c_str(), 0755) != 0 && errno != EEXIST) {
            cerr << "Error: Failed to create log directory " << logDir << ": " << strerror(errno) << endl;
            exit(1);
        }
        return logDir + "/firewall_manager.log";
    }
    static string getTimestamp() {
        auto now = chrono::system_clock::now();
        time_t tt = chrono::system_clock::to_time_t(now);
        tm local_tm;
        if (localtime_r(&tt, &local_tm) == nullptr) {
            return "TIME_ERROR";
        }
        char buffer[80];
        strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%S", &local_tm);
        return string(buffer);
    }
    static string encryptLog(const string& message) {
        return "[ENCRYPTED]" + message; // Placeholder
    }
    static string levelToString(LogLevel level) {
        switch (level) {
            case INFO: return "INFO";
            case WARNING: return "WARNING";
            case ERROR: return "ERROR";
            case DEBUG: return "DEBUG";
            default: return "UNKNOWN";
        }
    }
    // [AsyncLogger Patch #6] Expose simple metrics for debugging
    static json getQueueMetrics() {
        json j;
        j["queued"] = queuedCount.load();
        j["dropped"] = droppedLogs.load();
        j["max_capacity"] = MAX_LOG_QUEUE_SIZE;
        return j;
    }
    // [AsyncLogger Patch #3] Return cached timestamp string, refresh if older than TIMESTAMP_CACHE_MS
    static std::string getCachedTimestamp() {
        using namespace std::chrono;
        long long nowMs = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
        long long last = cachedTsMs.load(std::memory_order_relaxed);

        // Fast path: cache still valid
        if (nowMs - last < TIMESTAMP_CACHE_MS && !cachedTsStr.empty()) {
            return cachedTsStr;
        }

        // Slow path: update cached string under lock
        std::lock_guard<std::mutex> lock(cachedTsMutex);
        // Double-check after acquiring lock
        last = cachedTsMs.load(std::memory_order_relaxed);
        if (nowMs - last < TIMESTAMP_CACHE_MS && !cachedTsStr.empty()) {
            return cachedTsStr;
        }

        // Recompute formatted timestamp
        std::time_t tt = std::time(nullptr);
        std::tm tm_buf;
        localtime_r(&tt, &tm_buf); // thread-safe localtime
        char buf[64];
        size_t n = strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tm_buf);
        (void)n;
        // Append milliseconds
        int ms_part = (int)(nowMs % 1000);
        char finalBuf[80];
        snprintf(finalBuf, sizeof(finalBuf), "%s.%03d", buf, ms_part);

        cachedTsStr = std::string(finalBuf, strlen(finalBuf));
        cachedTsMs.store(nowMs, std::memory_order_relaxed);
        return cachedTsStr;
    }
    // [AsyncLogger Patch #1] Added batching constants for high-performance writer
    static constexpr size_t LOGGER_BATCH_SIZE = 128;
    static constexpr size_t LOGGER_FLUSH_INTERVAL_MS = 50;
    static void writerLoop() {
        // [AsyncLogger Patch #2] Switched to FILE* for high-performance buffered I/O
        FILE* fp = fopen(getLogFilePath().c_str(), "a");

        if (!fp) {
            std::cerr << "[Logger] Failed to open log file." << std::endl;
            return;
        }

        // [AsyncLogger Patch #2] Add large 64 KB buffer to improve write throughput
        static thread_local std::vector<char> logFileBuffer;
        logFileBuffer.resize(64 * 1024);  // 64KB buffer
        setvbuf(fp, logFileBuffer.data(), _IOFBF, logFileBuffer.size());

        while (true) {
            std::unique_lock<std::mutex> lock(logMutex);
            logCV.wait(lock, [] {
                return Logger::queuedCount.load(std::memory_order_relaxed) > 0 || !writerRunning.load();
            });

            if (!writerRunning.load() && Logger::queuedCount.load(std::memory_order_relaxed) == 0) {
                break;
            }

            // [AsyncLogger Patch #1] Implemented batch writes for performance
            std::string batchBuffer;
            batchBuffer.reserve(8192); // reserve space to minimize reallocs
            size_t collected = 0;

            LogRecord rec;
            // [AsyncLogger Patch #5] Helper to append processed records into the batch buffer
            auto appendRecord = [&](const LogRecord& record) {
                // [AsyncLogger Patch #3] Use cached timestamp to avoid per-line strftime
                batchBuffer.append(getCachedTimestamp());
                batchBuffer.append(" [");
                batchBuffer.append(levelToString(record.level));
                batchBuffer.append("] ");
                // [AsyncLogger Patch #4] If encryption disabled, fall back to raw message
                // [AsyncLogger Patch #4] Encrypt messages HERE in writer thread (not hot path)
                batchBuffer.append(encryptLog(record.msg));
                batchBuffer.push_back('\n');
            };

            // [AsyncLogger Patch #1] Release lock before performing disk I/O
            lock.unlock();

            // [AsyncLogger Patch #5] Drain lock-free producer queue first (fast path)
            while (collected < LOGGER_BATCH_SIZE && lfLogQueue.try_dequeue(rec)) {
                appendRecord(rec);
                collected++;
                // [AsyncLogger Patch #6] Decrement queue count after consuming record
                queuedCount.fetch_sub(1, std::memory_order_relaxed);
            }

            // [AsyncLogger Patch #5] Then drain fallback locked queue (rare)
            {
                std::lock_guard<std::mutex> fallbackLock(logMutex);
                while (collected < LOGGER_BATCH_SIZE && !fallbackLogQueue.empty()) {
                    rec = std::move(fallbackLogQueue.front());
                    fallbackLogQueue.pop();
                    appendRecord(rec);
                    collected++;
                    // [AsyncLogger Patch #6] Decrement queue count after consuming record
                    queuedCount.fetch_sub(1, std::memory_order_relaxed);
                }
            }

            // **Write entire batch at once**
            if (!batchBuffer.empty()) {
                // [AsyncLogger Patch #2] Using fwrite() for batch writes
                // [AsyncLogger Patch #1] Single syscall for entire batch
                fwrite(batchBuffer.data(), 1, batchBuffer.size(), fp);
            }

            // [AsyncLogger Patch #2] Explicit flush for FILE*
            static auto lastFlush = std::chrono::steady_clock::now();
            auto now = std::chrono::steady_clock::now();
            if (now - lastFlush >= std::chrono::milliseconds(LOGGER_FLUSH_INTERVAL_MS) || !writerRunning.load()) {
                fflush(fp);
                lastFlush = now;
            }
        }

        // [AsyncLogger Patch #2] Close FILE* safely at shutdown
        fclose(fp);
    }
};
Logger::LogLevel Logger::currentLevel = Logger::INFO;
// [AsyncLogger Patch #5] Define producer/consumer queues
moodycamel::ConcurrentQueue<LogRecord> Logger::lfLogQueue;
std::queue<LogRecord> Logger::fallbackLogQueue;
std::mutex Logger::logMutex;
std::condition_variable Logger::logCV;
std::atomic<bool> Logger::writerRunning{false};
std::thread Logger::writerThread;
// [AsyncLogger Patch #3] Define static cached timestamp variables
std::atomic<long long> Logger::cachedTsMs{0};
std::string Logger::cachedTsStr = "";
std::mutex Logger::cachedTsMutex;
// [AsyncLogger Patch #6] Initialize bounded-queue counters
std::atomic<size_t> Logger::queuedCount{0};
std::atomic<size_t> Logger::droppedLogs{0};
// NeuralNetwork class
class NeuralNetwork {
private:
    int inputSize;
    int hiddenSize1;
    int hiddenSize2;
    int outputSize;
    vector<vector<double>> weightsInputHidden1;
    vector<vector<double>> weightsHidden1Hidden2;
    vector<vector<double>> weightsHidden2Output;
    vector<double> biasHidden1;
    vector<double> biasHidden2;
    vector<double> biasOutput;
    double sigmoid(double x) {
        return 1.0 / (1.0 + exp(-x));
    }
    double sigmoidDerivative(double x) {
        return x * (1.0 - x);
    }
    vector<double> applyDropout(const vector<double>& layer, double dropoutRate) {
        vector<double> dropped = layer;
        random_device rd;
        mt19937 gen(rd());
        uniform_real_distribution<> dis(0.0, 1.0);
        for (auto& val : dropped) {
            if (dis(gen) < dropoutRate) {
                val = 0.0;
            } else {
                val /= (1.0 - dropoutRate);
            }
        }
        return dropped;
    }
public:
    vector<double> outputLayer;
    NeuralNetwork(int input, int hidden1, int hidden2, int output)
        : inputSize(input), hiddenSize1(hidden1), hiddenSize2(hidden2), outputSize(output) {
        random_device rd;
        mt19937 gen(rd());
        uniform_real_distribution<> dis(-0.5, 0.5);
        weightsInputHidden1.resize(inputSize, vector<double>(hiddenSize1));
        for (int i = 0; i < inputSize; ++i) {
            for (int j = 0; j < hiddenSize1; ++j) {
                weightsInputHidden1[i][j] = dis(gen);
            }
        }
        weightsHidden1Hidden2.resize(hiddenSize1, vector<double>(hiddenSize2));
        for (int i = 0; i < hiddenSize1; ++i) {
            for (int j = 0; j < hiddenSize2; ++j) {
                weightsHidden1Hidden2[i][j] = dis(gen);
            }
        }
        weightsHidden2Output.resize(hiddenSize2, vector<double>(outputSize));
        for (int i = 0; i < hiddenSize2; ++i) {
            for (int j = 0; j < outputSize; ++j) {
                weightsHidden2Output[i][j] = dis(gen);
            }
        }
        biasHidden1.resize(hiddenSize1);
        for (auto& b : biasHidden1) b = dis(gen);
        biasHidden2.resize(hiddenSize2);
        for (auto& b : biasHidden2) b = dis(gen);
        biasOutput.resize(outputSize);
        for (auto& b : biasOutput) b = dis(gen);
        outputLayer.resize(outputSize, 0.0);
    }
    void forwardPropagate(const vector<double>& inputs, double dropoutRate = 0.0) {
        vector<double> hidden1(hiddenSize1, 0.0);
        for (int j = 0; j < hiddenSize1; ++j) {
            for (int i = 0; i < inputSize; ++i) {
                hidden1[j] += inputs[i] * weightsInputHidden1[i][j];
            }
            hidden1[j] += biasHidden1[j];
            hidden1[j] = sigmoid(hidden1[j]);
        }
        hidden1 = applyDropout(hidden1, dropoutRate);
        vector<double> hidden2(hiddenSize2, 0.0);
        for (int j = 0; j < hiddenSize2; ++j) {
            for (int i = 0; i < hiddenSize1; ++i) {
                hidden2[j] += hidden1[i] * weightsHidden1Hidden2[i][j];
            }
            hidden2[j] += biasHidden2[j];
            hidden2[j] = sigmoid(hidden2[j]);
        }
        hidden2 = applyDropout(hidden2, dropoutRate);
        for (int j = 0; j < outputSize; ++j) {
            outputLayer[j] = 0.0;
            for (int i = 0; i < hiddenSize2; ++i) {
                outputLayer[j] += hidden2[i] * weightsHidden2Output[i][j];
            }
            outputLayer[j] += biasOutput[j];
            outputLayer[j] = sigmoid(outputLayer[j]);
        }
    }
    void backpropagate(const vector<double>& inputs, const vector<double>& targets, double learningRate) {
        vector<double> hidden1(hiddenSize1, 0.0);
        for (int j = 0; j < hiddenSize1; ++j) {
            for (int i = 0; i < inputSize; ++i) {
                hidden1[j] += inputs[i] * weightsInputHidden1[i][j];
            }
            hidden1[j] += biasHidden1[j];
            hidden1[j] = sigmoid(hidden1[j]);
        }
        vector<double> hidden2(hiddenSize2, 0.0);
        for (int j = 0; j < hiddenSize2; ++j) {
            for (int i = 0; i < hiddenSize1; ++i) {
                hidden2[j] += hidden1[i] * weightsHidden1Hidden2[i][j];
            }
            hidden2[j] += biasHidden2[j];
            hidden2[j] = sigmoid(hidden2[j]);
        }
        vector<double> outputs(outputSize, 0.0);
        for (int j = 0; j < outputSize; ++j) {
            for (int i = 0; i < hiddenSize2; ++i) {
                outputs[j] += hidden2[i] * weightsHidden2Output[i][j];
            }
            outputs[j] += biasOutput[j];
            outputs[j] = sigmoid(outputs[j]);
        }
        vector<double> outputErrors(outputSize);
        for (int j = 0; j < outputSize; ++j) {
            outputErrors[j] = (targets[j] - outputs[j]) * sigmoidDerivative(outputs[j]);
        }
        vector<double> hidden2Errors(hiddenSize2, 0.0);
        for (int j = 0; j < hiddenSize2; ++j) {
            for (int k = 0; k < outputSize; ++k) {
                hidden2Errors[j] += outputErrors[k] * weightsHidden2Output[j][k];
            }
            hidden2Errors[j] *= sigmoidDerivative(hidden2[j]);
        }
        vector<double> hidden1Errors(hiddenSize1, 0.0);
        for (int j = 0; j < hiddenSize1; ++j) {
            for (int k = 0; k < hiddenSize2; ++k) {
                hidden1Errors[j] += hidden2Errors[k] * weightsHidden1Hidden2[j][k];
            }
            hidden1Errors[j] *= sigmoidDerivative(hidden1[j]);
        }
        for (int i = 0; i < hiddenSize2; ++i) {
            for (int j = 0; j < outputSize; ++j) {
                weightsHidden2Output[i][j] += learningRate * outputErrors[j] * hidden2[i];
            }
        }
        for (int j = 0; j < outputSize; ++j) {
            biasOutput[j] += learningRate * outputErrors[j];
        }
        for (int i = 0; i < hiddenSize1; ++i) {
            for (int j = 0; j < hiddenSize2; ++j) {
                weightsHidden1Hidden2[i][j] += learningRate * hidden2Errors[j] * hidden1[i];
            }
        }
        for (int j = 0; j < hiddenSize2; ++j) {
            biasHidden2[j] += learningRate * hidden2Errors[j];
        }
        for (int i = 0; i < inputSize; ++i) {
            for (int j = 0; j < hiddenSize1; ++j) {
                weightsInputHidden1[i][j] += learningRate * hidden1Errors[j] * inputs[i];
            }
        }
        for (int j = 0; j < hiddenSize1; ++j) {
            biasHidden1[j] += learningRate * hidden1Errors[j];
        }
    }
    void train(const vector<vector<double>>& inputData, const vector<vector<double>>& targetData, int epochs, double learningRate, double dropoutRate = DROPOUT_RATE) {
        if (inputData.size() != targetData.size() || inputData.empty()) {
            Logger::log("Invalid training data size.", Logger::ERROR);
            return;
        }
        size_t numSamples = inputData.size();
        for (int epoch = 0; epoch < epochs; ++epoch) {
            double totalError = 0.0;
            for (size_t sample = 0; sample < numSamples; ++sample) {
                forwardPropagate(inputData[sample], dropoutRate);
                backpropagate(inputData[sample], targetData[sample], learningRate);
                for (int j = 0; j < outputSize; ++j) {
                    totalError += pow(targetData[sample][j] - outputLayer[j], 2);
                }
            }
            totalError /= numSamples;
            if (epoch % 50 == 0) {
                Logger::log("Epoch " + to_string(epoch) + "/" + to_string(epochs) + " - Average Error: " + to_string(totalError), Logger::DEBUG);
            }
        }
        Logger::log("Training completed.", Logger::INFO);
    }
    bool detectThreat() {
        return outputLayer[0] > THREAT_THRESHOLD;
    }
    void saveModel(const string& filename) {
        json j;
        j["inputSize"] = inputSize;
        j["hiddenSize1"] = hiddenSize1;
        j["hiddenSize2"] = hiddenSize2;
        j["outputSize"] = outputSize;
        j["weightsInputHidden1"] = weightsInputHidden1;
        j["weightsHidden1Hidden2"] = weightsHidden1Hidden2;
        j["weightsHidden2Output"] = weightsHidden2Output;
        j["biasHidden1"] = biasHidden1;
        j["biasHidden2"] = biasHidden2;
        j["biasOutput"] = biasOutput;
        ofstream file(filename);
        if (file.is_open()) {
            file << j.dump(4);
            file.close();
            Logger::log("Model saved to " + filename, Logger::INFO);
        } else {
            Logger::log("Failed to save model.", Logger::ERROR);
        }
    }
    void loadModel(const string& filename) {
        ifstream file(filename);
        if (!file.is_open()) {
            Logger::log("Failed to open model file " + filename, Logger::ERROR);
            return;
        }
        json j;
        try {
            file >> j;
            inputSize = j["inputSize"];
            hiddenSize1 = j["hiddenSize1"];
            hiddenSize2 = j["hiddenSize2"];
            outputSize = j["outputSize"];
            weightsInputHidden1 = j["weightsInputHidden1"].get<vector<vector<double>>>();
            weightsHidden1Hidden2 = j["weightsHidden1Hidden2"].get<vector<vector<double>>>();
            weightsHidden2Output = j["weightsHidden2Output"].get<vector<vector<double>>>();
            biasHidden1 = j["biasHidden1"].get<vector<double>>();
            biasHidden2 = j["biasHidden2"].get<vector<double>>();
            biasOutput = j["biasOutput"].get<vector<double>>();
            outputLayer.resize(outputSize, 0.0);
            Logger::log("Model loaded from " + filename, Logger::INFO);
        } catch (const exception& e) {
            Logger::log("Error loading model: " + string(e.what()), Logger::ERROR);
        }
        file.close();
    }
};
// PacketSniffer class
class PacketSniffer {
private:
    pcap_t* handle;
    string device;
    thread sniffThread;
    FirewallManager* manager;
    atomic<bool> sniffing;
public:
    PacketSniffer(const string& dev, FirewallManager* mgr) : device(dev), manager(mgr), sniffing(false) {}
    bool start() {
        char errbuf[PCAP_ERRBUF_SIZE];
        handle = pcap_open_live(device.c_str(), BUFSIZ, 1, 1000, errbuf);
        if (!handle) {
            Logger::log("Failed to open device " + device + ": " + errbuf, Logger::ERROR);
            return false;
        }
        struct bpf_program fp;
        if (pcap_compile(handle, &fp, "ip", 0, PCAP_NETMASK_UNKNOWN) == -1 || pcap_setfilter(handle, &fp) == -1) {
            Logger::log("Failed to set packet filter.", Logger::ERROR);
            pcap_close(handle);
            return false;
        }
        sniffing = true;
        sniffThread = thread([this]() {
            pcap_loop(handle, 0, packetCallback, reinterpret_cast<u_char*>(manager));
        });
        Logger::log("Packet sniffing started on " + device, Logger::INFO);
        return true;
    }
    void stop() {
        if (sniffing.load()) {
            pcap_breakloop(handle);
            if (sniffThread.joinable()) sniffThread.join();
            pcap_close(handle);
            sniffing = false;
            Logger::log("Packet sniffing stopped.", Logger::INFO);
        }
    }
    static void packetCallback(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet);
};
// ThreatIntelligenceIntegrator class
class ThreatIntelligenceIntegrator {
private:
    CURL* curl;
    string apiUrl;
public:
    ThreatIntelligenceIntegrator(const string& url) : apiUrl(url) {
        curl = curl_easy_init();
        if (!curl) {
            Logger::log("Failed to initialize CURL for threat intel.", Logger::ERROR);
        }
    }
    ~ThreatIntelligenceIntegrator() {
        if (curl) curl_easy_cleanup(curl);
    }
    bool isThreatIP(const string& ip) {
        (void)ip; // Suppress unused parameter warning
        Logger::log("Threat intel disabled for testing.", Logger::INFO);
        return false;
    }
};
// FirewallManager class
class FirewallManager {
private:
    unique_ptr<NeuralNetwork> neuralNetwork;
    vector<vector<double>> trainingData;
    vector<vector<double>> trainingLabels;
    map<string, ConnectionState> connectionTable;
    unordered_map<string, int> ipConnectionCounts;
    set<string> blockedIPs;
    map<string, BlockedDomain> blockedDomains;
    bool panicModeEnabled = false;
    bool internetStatus = false;
    CURL* curl;
    PacketSniffer sniffer;
    ThreatIntelligenceIntegrator threatIntel;
    thread threatMonitorThread;
    thread maintenanceThread;
    condition_variable cv;
    queue<NetworkTrafficData> trafficQueue;
    string executeSystemCommand(const string& cmd) {
        FILE* pipe = popen(cmd.c_str(), "r");
        if (!pipe) {
            Logger::log("Failed to execute command: " + cmd, Logger::ERROR);
            return "";
        }
        char buffer[128];
        string result;
        while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            result += buffer;
        }
        int exitCode = pclose(pipe);
        if (exitCode != 0) {
            Logger::log("Command " + cmd + " exited with code " + to_string(exitCode), Logger::WARNING);
        }
        return result;
    }
    void initializeNeuralNetwork() {
        neuralNetwork = make_unique<NeuralNetwork>(4, 8, 4, 1);
        if (ifstream(MODEL_FILE).good()) {
            neuralNetwork->loadModel(MODEL_FILE);
        } else {
            Logger::log("No model file found, initializing new neural network.", Logger::INFO);
        }
    }
public:
    FirewallManager(const string& interface = "eth0") : sniffer(interface, this), threatIntel(THREAT_INTEL_API) {
        initializeNeuralNetwork();
        curl = curl_easy_init();
        if (!curl) Logger::log("CURL initialization failed.", Logger::ERROR);
        loadBlockedIPs();
        loadBlockedDomains();
        blockedIPsPtr = &blockedIPs;
        blockedDomainsPtr = &blockedDomains;
        if (!sniffer.start()) {
            Logger::log("Failed to start packet sniffer.", Logger::ERROR);
        }
        threatMonitorThread = thread(&FirewallManager::threatMonitor, this);
        maintenanceThread = thread(&FirewallManager::systemMaintenance, this);
    }
    ~FirewallManager() {
        running = false;
        cv.notify_all();
        sniffer.stop();
        if (threatMonitorThread.joinable()) threatMonitorThread.join();
        if (maintenanceThread.joinable()) maintenanceThread.join();
        if (curl) curl_easy_cleanup(curl);
        saveBlockedIPs();
        saveBlockedDomains();
        neuralNetwork->saveModel(MODEL_FILE);
    }
    void loadBlockedIPs() {
        ifstream file(BLOCKED_IPS_FILE);
        if (file.is_open()) {
            json j;
            file >> j;
            for (const auto& ip : j["blocked_ips"]) {
                blockedIPs.insert(ip);
            }
            file.close();
            Logger::log("Loaded " + to_string(blockedIPs.size()) + " blocked IPs.", Logger::INFO);
        }
    }
    void saveBlockedIPs() {
        json j;
        j["blocked_ips"] = vector<string>(blockedIPs.begin(), blockedIPs.end());
        ofstream file(BLOCKED_IPS_FILE);
        if (file.is_open()) {
            file << j.dump(4);
            file.close();
            Logger::log("Saved blocked IPs to file.", Logger::INFO);
        } else {
            Logger::log("Failed to save blocked IPs.", Logger::ERROR);
        }
    }
    void loadBlockedDomains() {
        ifstream file(BLOCKED_DOMAINS_FILE);
        if (!file.is_open()) {
            Logger::log("No blocked domains file found.", Logger::INFO);
            return;
        }
        json j;
        try {
            file >> j;
            for (const auto& domain : j["blocked_domains"]) {
                BlockedDomain bd;
                bd.domain = domain["domain"];
                bd.category = domain["category"];
                for (const auto& ip : domain["resolvedIPs"]) {
                    bd.resolvedIPs.insert(ip.get<string>());
                    blockedIPs.insert(ip.get<string>());
                }
                blockedDomains[bd.domain] = bd;
            }
            file.close();
            Logger::log("Loaded " + to_string(blockedDomains.size()) + " blocked domains.", Logger::INFO);
        } catch (const exception& e) {
            Logger::log("Error loading blocked domains: " + string(e.what()), Logger::ERROR);
        }
    }
    void saveBlockedDomains() {
        json j;
        vector<json> domains;
        for (const auto& pair : blockedDomains) {
            json domain;
            domain["domain"] = pair.first;
            domain["category"] = pair.second.category;
            domain["resolvedIPs"] = vector<string>(pair.second.resolvedIPs.begin(), pair.second.resolvedIPs.end());
            domains.push_back(domain);
        }
        j["blocked_domains"] = domains;
        ofstream file(BLOCKED_DOMAINS_FILE);
        if (file.is_open()) {
            file << j.dump(4);
            file.close();
            Logger::log("Saved blocked domains to file.", Logger::INFO);
        } else {
            Logger::log("Failed to save blocked domains.", Logger::ERROR);
        }
    }
    string getDomainCategory(const string& domain) {
        if (!curl) {
            Logger::log("CURL not initialized for category lookup.", Logger::ERROR);
            return "unknown";
        }
        string url = "https://api.webshrinker.com/categories/v3/" + domain; // Example API - replace with actual
        string response;
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, [](char* ptr, size_t size, size_t nmemb, void* userdata) -> size_t {
            ((string*)userdata)->append(ptr, size * nmemb);
            return size * nmemb;
        });
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, "Authorization: Bearer YOUR_API_KEY");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        CURLcode res = curl_easy_perform(curl);
        curl_slist_free_all(headers);
        if (res == CURLE_OK) {
            try {
                json j = json::parse(response);
                if (j.contains("categories") && !j["categories"].empty()) {
                    return j["categories"][0].get<string>();
                }
            } catch (const exception& e) {
                Logger::log("Category parse error for " + domain + ": " + e.what(), Logger::ERROR);
            }
        } else {
            Logger::log("Category request failed for " + domain + ": " + curl_easy_strerror(res), Logger::ERROR);
        }
        return "unknown";
    }
    void blockDomain(const string& domain, const string& category = "") {
        struct addrinfo hints, *res;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        int status = getaddrinfo(domain.c_str(), nullptr, &hints, &res);
        if (status != 0) {
            Logger::log("Failed to resolve " + domain + ": " + gai_strerror(status), Logger::ERROR);
            cout << "Failed to resolve " + domain + ": " + gai_strerror(status) << endl;
            return;
        }
        string resolvedCategory = category.empty() ? getDomainCategory(domain) : category;
        BlockedDomain blockedDomain;
        blockedDomain.domain = domain;
        blockedDomain.category = resolvedCategory;
        char ipStr[INET_ADDRSTRLEN];
        for (struct addrinfo* p = res; p != nullptr; p = p->ai_next) {
            void* addr = &((struct sockaddr_in*)p->ai_addr)->sin_addr;
            inet_ntop(p->ai_family, addr, ipStr, sizeof(ipStr));
            string ip = ipStr;
            if (blockedIPs.count(ip) == 0) {
                string cmd = "firewall-cmd --permanent --add-rich-rule='rule family=\"ipv4\" source address=\"" + ip + "\" drop'";
                executeSystemCommand(cmd);
                blockedIPs.insert(ip);
                blockedDomain.resolvedIPs.insert(ip);
                Logger::log("Blocked IP " + ip + " for domain " + domain, Logger::WARNING);
            }
        }
        freeaddrinfo(res);
        executeSystemCommand("firewall-cmd --reload");
        lock_guard<mutex> lock(globalMutex);
        blockedDomains[domain] = blockedDomain;
        saveBlockedDomains();
        Logger::log("Blocked domain " + domain + " (category: " + blockedDomain.category + ")", Logger::INFO);
        cout << "Blocked domain " + domain + " (category: " + blockedDomain.category + ")" << endl;
    }
    void unblockDomain(const string& domain) {
        lock_guard<mutex> lock(globalMutex);
        auto it = blockedDomains.find(domain);
        if (it == blockedDomains.end()) {
            Logger::log("Domain " + domain + " not blocked.", Logger::INFO);
            cout << "Domain " + domain + " not blocked." << endl;
            return;
        }
        for (const auto& ip : it->second.resolvedIPs) {
            if (blockedIPs.count(ip) > 0) {
                string cmd = "firewall-cmd --permanent --remove-rich-rule='rule family=\"ipv4\" source address=\"" + ip + "\" drop'";
                executeSystemCommand(cmd);
                blockedIPs.erase(ip);
                Logger::log("Unblocked IP " + ip + " for domain " + domain, Logger::INFO);
            }
        }
        executeSystemCommand("firewall-cmd --reload");
        blockedDomains.erase(it);
        saveBlockedDomains();
        Logger::log("Unblocked domain " + domain, Logger::INFO);
        cout << "Unblocked domain " + domain << endl;
    }
    void blockCategory(const string& category) {
    lock_guard<mutex> lock(globalMutex);
    vector<string> domains;
    if (category == "sports") {
        domains = {"espn.com", "nfl.com", "nba.com", "cbssports.com", "mlb.com",
                   "nhl.com", "foxsports.com", "si.com", "bleacherreport.com",
                   "sportingnews.com", "nbcsports.com", "theathletic.com",
                   "sbnation.com", "goal.com", "skysports.com", "eurosport.com",
                   "sportbible.com", "deadspin.com", "yardbarker.com", "thescore.com",
                   "espncricinfo.com", "cricket.com.au", "fifa.com", "uefa.com",
                   "olympics.com", "golf.com", "pgatour.com", "tennis.com",
                   "atptour.com", "wtatennis.com", "runnersworld.com", "bicycling.com",
                   "swimmingworldmagazine.com", "espnfc.com", "mlssoccer.com",
                   "nascar.com", "formula1.com", "motorsport.com", "cyclingnews.com",
                   "boxingscene.com", "mmafighting.com", "sherdog.com", "rugbypass.com",
                   "worldrugby.org", "hockeynews.com", "lacrossetribune.com",
                   "trackandfieldnews.com", "sport360.com", "talksport.com",
                   "givemesport.com", "sportstar.thehindu.com", "90min.com"};
    } else if (category == "news") {
        domains = {"cnn.com", "bbc.com", "nytimes.com", "reuters.com",
                   "theguardian.com", "apnews.com", "npr.org", "aljazeera.com",
                   "wsj.com", "washingtonpost.com", "bloomberg.com", "ft.com",
                   "abcnews.go.com", "cbsnews.com", "nbcnews.com", "usatoday.com",
                   "foxnews.com", "newsweek.com", "time.com", "huffpost.com",
                   "politico.com", "axios.com", "vox.com", "slate.com",
                   "thehill.com", "nypost.com", "dailymail.co.uk", "telegraph.co.uk",
                   "independent.co.uk", "mirror.co.uk", "express.co.uk", "skynews.com",
                   "cnbc.com", "forbes.com", "businessinsider.com", "news.com.au",
                   "smh.com.au", "theage.com.au", "japantimes.co.jp", "france24.com",
                   "dw.com", "rt.com", "spiegel.de", "lemonde.fr", "elpais.com",
                   "timesofindia.indiatimes.com", "hindustantimes.com", "straitstimes.com",
                   "scmp.com", "nationalpost.com", "globeandmail.com"};
    } else if (category == "technology") {
        domains = {"techcrunch.com", "wired.com", "theverge.com", "arstechnica.com",
                   "cnet.com", "engadget.com", "gizmodo.com", "zdnet.com",
                   "techradar.com", "mashable.com", "venturebeat.com", "digitaltrends.com",
                   "thenextweb.com", "geekwire.com", "bgr.com", "slashgear.com",
                   "tomshardware.com", "anandtech.com", "pcmag.com", "computerworld.com",
                   "itworld.com", "infoworld.com", "networkworld.com", "techrepublic.com",
                   "gadgethacks.com", "makeuseof.com", "howtogeek.com", "lifehacker.com",
                   "androidauthority.com", "9to5mac.com", "9to5google.com",
                   "androidcentral.com", "appleinsider.com", "pocket-lint.com",
                   "trustedreviews.com", "techspot.com", "extremetech.com",
                   "hardwarezone.com", "overclock.net", "linustechtips.com",
                   "arstechnica.co.uk", "techadvisor.com", "windowscentral.com",
                   "macrumors.com", "droid-life.com", "phonearena.com", "gsmarena.com",
                   "xda-developers.com", "ventureburn.com", "siliconangle.com",
                   "betanews.com"};
    } else if (category == "entertainment") {
        domains = {"variety.com", "hollywoodreporter.com", "ew.com", "tmz.com",
                   "eonline.com", "vulture.com", "deadline.com", "rollingstone.com",
                   "billboard.com", "mtv.com", "people.com", "usmagazine.com",
                   "etonline.com", "accessonline.com", "popsugar.com", "justjared.com",
                   "screenrant.com", "collider.com", "indiewire.com", "slashfilm.com",
                   "cinemablend.com", "movieweb.com", "comingsoon.net", "joblo.com",
                   "fandango.com", "rottentomatoes.com", "metacritic.com", "imdb.com",
                   "tvguide.com", "tvline.com", "teenvogue.com", "vanityfair.com",
                   "gq.com", "vogue.com", "elle.com", "harpersbazaar.com",
                   "cosmopolitan.com", "glamour.com", "instyle.com", "esquire.com",
                   "nme.com", "pitchfork.com", "stereogum.com", "consequence.net",
                   "avclub.com", "denofgeek.com", "screendaily.com", "thewrap.com",
                   "bustle.com", "refinery29.com", "complex.com"};
    } else if (category == "finance") {
        domains = {"bloomberg.com", "cnbc.com", "marketwatch.com", "forbes.com",
                   "businessinsider.com", "ft.com", "wsj.com", "investopedia.com",
                   "fool.com", "barrons.com", "kiplinger.com", "money.cnn.com",
                   "thestreet.com", "morningstar.com", "seekingalpha.com", "zacks.com",
                   "benzinga.com", "nasdaq.com", "nyse.com", "investorplace.com",
                   "financialpost.com", "economist.com", "moneycontrol.com",
                   "livemint.com", "etf.com", "bankrate.com", "nerdwallet.com",
                   "creditkarma.com", "smartasset.com", "thebalance.com",
                   "valuepenguin.com", "moneycrashers.com", "business-standard.com",
                   "economictimes.indiatimes.com", "finance.yahoo.com", "cnbctv18.com",
                   "marketrealist.com", "themotleyfool.com", "tipranks.com",
                   "barchart.com", "tradingview.com", "investing.com", "finviz.com",
                   "stockcharts.com", "bloombergquint.com", "moneyweek.com",
                   "financialexpress.com", "ibtimes.com", "dailyfx.com",
                   "fxstreet.com", "forexlive.com"};
    } else if (category == "health") {
        domains = {"webmd.com", "mayoclinic.org", "healthline.com", "medscape.com",
                   "nih.gov", "cdc.gov", "who.int", "medicalnewstoday.com",
                   "everydayhealth.com", "health.com", "menshealth.com", "womenshealthmag.com",
                   "prevention.com", "verywellhealth.com", "psychologytoday.com",
                   "healthgrades.com", "drugs.com", "rxlist.com", "merckmanuals.com",
                   "medlineplus.gov", "livestrong.com", "self.com", "shape.com",
                   "eatingwell.com", "myfitnesspal.com", "fitbit.com", "mensjournal.com",
                   "runnersworld.com", "yogajournal.com", "mindbodygreen.com",
                   "health.harvard.edu", "clevelandclinic.org", "hopkinsmedicine.org",
                   "diabetes.org", "heart.org", "cancer.org", "arthritis.org",
                   "psychcentral.com", "verywellmind.com", "verywellfit.com",
                   "nutrition.org", "eatright.org", "foodnetwork.com", "cookinglight.com",
                   "bonappetit.com", "epicurious.com", "seriouseats.com", "healthcentral.com",
                   "spine-health.com", "sleepfoundation.org", "drweil.com"};
    } else if (category == "travel") {
        domains = {"tripadvisor.com", "lonelyplanet.com", "expedia.com", "booking.com",
                   "kayak.com", "travelandleisure.com", "cntraveler.com", "fodors.com",
                   "frommers.com", "roughguides.com", "skyscanner.com", "orbitz.com",
                   "travelocity.com", "hotels.com", "agoda.com", "trivago.com",
                   "viator.com", "airbnb.com", "vrbo.com", "homeaway.com",
                   "nationalgeographic.com", "atlasobscura.com", "thepointsguy.com",
                   "travelzoo.com", "ricksteves.com", "budgettravel.com", "afar.com",
                   "matadornetwork.com", "nomadicmatt.com", "travelpulse.com",
                   "smartertravel.com", "oyster.com", "jetsetter.com", "luxurytraveladvisor.com",
                   "condenasttraveller.com", "travelweekly.com", "wanderlust.co.uk",
                   "cntraveller.in", "backpacker.com", "outsideonline.com",
                   "adventure.com", "tourradar.com", "intrepidtravel.com", "gadventures.com",
                   "cruisecritic.com", "cruise.com", "vacationstogo.com", "cruiseline.com",
                   "travelchannel.com", "flightaware.com", "seatguru.com"};
    } else if (category == "education") {
        domains = {"coursera.org", "edx.org", "khanacademy.org", "udemy.com",
                   "futurelearn.com", "pluralsight.com", "skillshare.com", "lynda.com",
                   "codecademy.com", "udacity.com", "brilliant.org", "masterclass.com",
                   "study.com", "chegg.com", "quizlet.com", "duolingo.com",
                   "memrise.com", "brainly.com", "sparknotes.com", "cliffnotes.com",
                   "openculture.com", "ted.com", "mit.edu", "stanford.edu",
                   "harvard.edu", "yale.edu", "ox.ac.uk", "cam.ac.uk", "edx.org",
                   "open.edu", "academic.oup.com", "jstor.org", "scholar.google.com",
                   "researchgate.net", "academia.edu", "springer.com", "elsevier.com",
                   "wiley.com", "tandfonline.com", "sagepub.com", "eric.ed.gov",
                   "nces.ed.gov", "education.com", "scholastic.com", "pbslearningmedia.org",
                   "nationalgeographic.org", "britannica.com", "merriam-webster.com",
                   "dictionary.com", "thesaurus.com", "grammarly.com"};
    } else if (category == "lifestyle") {
        domains = {"popsugar.com", "refinery29.com", "bustle.com", "elle.com",
                   "vogue.com", "gq.com", "esquire.com", "harpersbazaar.com",
                   "cosmopolitan.com", "glamour.com", "instyle.com", "teenvogue.com",
                   "marthastewart.com", "realsimple.com", "betterhomesandgardens.com",
                   "hgtv.com", "housebeautiful.com", "architecturaldigest.com",
                   "dwell.com", "apartmenttherapy.com", "elledecor.com", "veranda.com",
                   "goodhousekeeping.com", "countryliving.com", "southernliving.com",
                   "myrecipes.com", "epicurious.com", "bonappetit.com", "seriouseats.com",
                   "foodandwine.com", "delish.com", "thekitchn.com", "allrecipes.com",
                   "foodnetwork.com", "cookinglight.com", "tasteofhome.com",
                   "purewow.com", "goop.com", "mindbodygreen.com", "wellandgood.com",
                   "thecut.com", "manrepeller.com", "whowhatwear.com", "fashionista.com",
                   "racked.com", "stylecaster.com", "byrdie.com", "cupcakesandcashmere.com",
                   "lovelyish.com", "theeverygirl.com", "galmeetsglam.com"};
    } else if (category == "science") {
        domains = {"sciencemag.org", "nature.com", "sciencedaily.com", "scientificamerican.com",
                   "newscientist.com", "livescience.com", "space.com", "astronomy.com",
                   "discovermagazine.com", "popsci.com", "nationalgeographic.com",
                   "smithsonianmag.com", "sciencenews.org", "phys.org", "arstechnica.com",
                   "wired.com", "the-scientist.com", "eurekalert.org", "sciencedirect.com",
                   "plos.org", "frontiersin.org", "springer.com", "elsevier.com",
                   "researchgate.net", "pubmed.ncbi.nlm.nih.gov", "scholar.google.com",
                   "nasa.gov", "esa.int", "cern.ch", "quantum.gov", "energy.gov",
                   "noaa.gov", "usgs.gov", "nih.gov", "nsf.gov", "sciencenewsforstudents.org",
                   "askascientist.com", "sciencefocus.com", "cosmosmagazine.com",
                   "sciencealert.com", "futurism.com", "quantamagazine.org",
                   "newatlas.com", "sciencetimes.com", "theconversation.com",
                   "nautil.us", "sciencefriday.com", "skyandtelescope.com",
                   "earthsky.org", "universetoday.com", "physicsworld.com"};
    } else if (category == "gaming") {
        domains = {"ign.com", "gamespot.com", "polygon.com", "kotaku.com",
                   "eurogamer.net", "pcgamer.com", "rockpapershotgun.com", "gamesradar.com",
                   "gameinformer.com", "destructoid.com", "joystiq.com", "shacknews.com",
                   "vg247.com", "escapistmagazine.com", "gamezebo.com", "toucharcade.com",
                   "pocketgamer.com", "nintendolife.com", "pushsquare.com", "purexbox.com",
                   "gamesindustry.biz", "gamasutra.com", "venturebeat.com", "mmorpg.com",
                   "rpgsite.net", "dualshockers.com", "wccftech.com", "thegamer.com",
                   "gamepur.com", "gamingbolt.com", "techraptor.net", "hardcoregamer.com",
                   "gamecrate.com", "playstationlifestyle.net", "xboxachievements.com",
                   "trueachievements.com", "truegaming.net", "gameskinny.com",
                   "gameranx.com", "gamerevolution.com", "n4g.com", "gamespark.com",
                   "gamefront.com", "gamersheroes.com", "gamerant.com", "gamespew.com",
                   "indiegamewebsite.com", "indiegamesplus.com", "freegames.com",
                   "epicgames.com", "steamcommunity.com"};
    } else if (category == "food") {
        domains = {"foodnetwork.com", "bonappetit.com", "epicurious.com", "seriouseats.com",
                   "allrecipes.com", "thekitchn.com", "delish.com", "tasteofhome.com",
                   "foodandwine.com", "cookinglight.com", "myrecipes.com", "eatingwell.com",
                   "saveur.com", "food52.com", "smittenkitchen.com", "seriouseats.com",
                   "yummly.com", "bbcgoodfood.com", "jamieoliver.com", "nigella.com",
                   "marthastewart.com", "pioneerwoman.com", "halfbakedharvest.com",
                   "pinchofyum.com", "budgetbytes.com", "minimalistbaker.com",
                   "sallysbakingaddiction.com", "joyofbaking.com", "kingarthurbaking.com",
                   "tasty.co", "deliaonline.com", "greatbritishchefs.com", "gourmettraveller.com.au",
                   "taste.com.au", "foodrepublic.com", "eater.com", "thespruceeats.com",
                   "simplyrecipes.com", "cookieandkate.com", "loveandlemons.com",
                   "101cookbooks.com", "ohsheglows.com", "downshiftology.com",
                   "themediterraneandish.com", "skinnytaste.com", "gimmesomeoven.com",
                   "averiecooks.com", "cafedelites.com", "damn-delicious.com",
                   "bakingmischief.com", "justonecookbook.com", "recipetineats.com"};
    } else if (category == "fashion") {
        domains = {"vogue.com", "elle.com", "harpersbazaar.com", "gq.com",
                   "esquire.com", "instyle.com", "cosmopolitan.com", "glamour.com",
                   "teenvogue.com", "whowhatwear.com", "fashionista.com", "thecut.com",
                   "manrepeller.com", "stylecaster.com", "byrdie.com", "refinery29.com",
                   "popsugar.com", "bustle.com", "racked.com", "coveteur.com",
                   "elleuk.com", "vogue.co.uk", "harpersbazaar.com.au", "vogue.in",
                   "gqindia.in", "ellecanada.com", "fashionmagazine.com", "vogue.fr",
                   "elle.fr", "gqmagazine.fr", "vogue.it", "elle.it", "vogue.es",
                   "elle.es", "gq.com.au", "vogue.com.au", "whowhatwear.co.uk",
                   "net-a-porter.com", "farfetch.com", "ssense.com", "matchesfashion.com",
                   "mytheresa.com", "modaoperandi.com", "shopstyle.com", "revolve.com",
                   "zara.com", "hm.com", "uniqlo.com", "nordstrom.com", "saksfifthavenue.com",
                   "bloomingdales.com"};
    } else {
        Logger::log("Category " + category + " not supported.", Logger::WARNING);
        cout << "Category " + category + " not supported." << endl;
    }
    for (const auto& domain : domains) {
        blockDomain(domain, category);
    }
    Logger::log("Blocked all domains in category: " + category, Logger::INFO);
    cout << "Blocked all domains in category: " + category << endl;
    }
   
    void unblockCategory(const string& category) {
        lock_guard<mutex> lock(globalMutex);
        vector<string> domainsToUnblock;
        for (const auto& pair : blockedDomains) {
            if (pair.second.category == category) {
                domainsToUnblock.push_back(pair.first);
            }
        }
        for (const auto& domain : domainsToUnblock) {
            unblockDomain(domain);
        }
        Logger::log("Unblocked all domains in category: " + category, Logger::INFO);
        cout << "Unblocked all domains in category: " + category << endl;
    }
    void exportBlockedIPsToCSV(const string& filename) {
        ofstream file(filename);
        if (!file.is_open()) {
            Logger::log("Failed to open file for exporting blocked IPs: " + filename, Logger::ERROR);
            return;
        }
        file << "Blocked IPs\n";
        for (const auto& ip : blockedIPs) {
            file << ip << "\n";
        }
        file.close();
        Logger::log("Blocked IPs exported to " + filename, Logger::INFO);
    }
    NetworkFeatures extractFeatures(const ConnectionState& connection) {
        NetworkFeatures features;
        try {
            double port = stod(connection.destPort);
            features.portNumber = port / 65535.0;
        } catch (const exception& e) {
            features.portNumber = 0.0;
            Logger::log("Invalid port number: " + connection.destPort, Logger::WARNING);
        }
        auto now = chrono::system_clock::now();
        double timeDiff = chrono::duration<double>(now - connection.lastUpdate).count();
        features.packetRate = (timeDiff > 0.0) ? static_cast<double>(connection.packetCount) / timeDiff : 0.0;
        features.packetSize = static_cast<double>(connection.totalBytes) / (1024.0 * 1024.0);
        features.connectionDuration = timeDiff / 3600.0;
        return features;
    }
    vector<double> convertToVector(const NetworkFeatures& features) {
        return {features.packetRate, features.packetSize, features.connectionDuration, features.portNumber};
    }
    void logError(const string &message) { Logger::log(message, Logger::ERROR); }
    void logWarning(const string &message) { Logger::log(message, Logger::WARNING); }
    void logInfo(const string &message) { Logger::log(message, Logger::INFO); }
    void addNatRule(const string &sourceIP, const string &destIP, const string &port) {
        string cmd = "firewall-cmd --permanent --add-rich-rule='rule family=\"ipv4\" source address=\"" + sourceIP + "\" destination address=\"" + destIP + "\" port port=\"" + port + "\" protocol=\"tcp\" accept'";
        executeSystemCommand(cmd);
        executeSystemCommand("firewall-cmd --reload");
        Logger::log("Added NAT rule: " + sourceIP + " -> " + destIP + ":" + port, Logger::INFO);
    }
    void removeNatRule(const string &ruleID) {
        string cmd = "firewall-cmd --permanent --remove-rich-rule='" + ruleID + "'";
        executeSystemCommand(cmd);
        executeSystemCommand("firewall-cmd --reload");
        Logger::log("Removed NAT rule: " + ruleID, Logger::INFO);
    }
    void checkInternetConnectivity() {
        string cmd = "ping -c 1 -W 2 google.com > /dev/null 2>&1";
        int status = system(cmd.c_str());
        internetStatus = (status == 0);
        if (internetStatus) {
            Logger::log("Internet is available.", Logger::INFO);
            cout << "Internet is available." << endl;
        } else {
            Logger::log("Internet is not available.", Logger::INFO);
            cout << "Internet is not available." << endl;
        }
    }
    void connectToVpn(const string &configPath) {
        if (configPath.empty() || access(configPath.c_str(), F_OK) != 0) {
            Logger::log("Invalid VPN config path: " + configPath, Logger::ERROR);
            return;
        }
        string cmd = "openvpn --config " + configPath + " &";
        system(cmd.c_str());
        Logger::log("VPN connection initiated with config " + configPath, Logger::INFO);
        cout << "VPN connection initiated with config " << configPath << endl;
    }
    void disconnectVpn() {
        system("pkill openvpn");
        Logger::log("VPN disconnected.", Logger::INFO);
        cout << "VPN disconnected." << endl;
    }
    bool isVpnConnected() {
        string output = executeSystemCommand("pgrep openvpn");
        return !output.empty();
    }
    void togglePanicMode() {
        panicModeEnabled = !panicModeEnabled;
        string cmd = "firewall-cmd --panic-" + string(panicModeEnabled ? "on" : "off");
        executeSystemCommand(cmd);
        Logger::log(panicModeEnabled ? "Panic mode enabled - All traffic blocked." : "Panic mode disabled - Traffic restored.", Logger::WARNING);
        cout << (panicModeEnabled ? "Panic mode enabled - All traffic blocked." : "Panic mode disabled - Traffic restored.") << endl;
    }
    void blockAllTraffic() {
        executeSystemCommand("firewall-cmd --panic-on");
        Logger::log("All traffic blocked.", Logger::WARNING);
        cout << "All traffic blocked." << endl;
    }
    void unblockAllTraffic() {
        executeSystemCommand("firewall-cmd --panic-off");
        Logger::log("All traffic unblocked.", Logger::INFO);
        cout << "All traffic unblocked." << endl;
    }
    void blockIPAddress(const string &ipAddress) {
        if (blockedIPs.count(ipAddress) > 0) {
            Logger::log("IP " + ipAddress + " already blocked.", Logger::INFO);
            cout << "IP " + ipAddress + " already blocked." << endl;
            return;
        }
        if (threatIntel.isThreatIP(ipAddress)) {
            string cmd = "firewall-cmd --permanent --add-rich-rule='rule family=\"ipv4\" source address=\"" + ipAddress + "\" drop'";
            executeSystemCommand(cmd);
            executeSystemCommand("firewall-cmd --reload");
            blockedIPs.insert(ipAddress);
            Logger::log("Blocked IP " + ipAddress + " (threat intel confirmed).", Logger::WARNING);
            cout << "Blocked IP " + ipAddress + " (threat intel confirmed)." << endl;
        } else {
            Logger::log("IP " + ipAddress + " not a known threat, not blocking.", Logger::INFO);
            cout << "IP " + ipAddress + " not a known threat, not blocking." << endl;
        }
    }
    void unblockIPAddress(const string &ipAddress) {
        if (blockedIPs.count(ipAddress) == 0) {
            Logger::log("IP " + ipAddress + " not blocked.", Logger::INFO);
            cout << "IP " + ipAddress + " not blocked." << endl;
            return;
        }
        string cmd = "firewall-cmd --permanent --remove-rich-rule='rule family=\"ipv4\" source address=\"" + ipAddress + "\" drop'";
        executeSystemCommand(cmd);
        executeSystemCommand("firewall-cmd --reload");
        blockedIPs.erase(ipAddress);
        Logger::log("Unblocked IP " + ipAddress, Logger::INFO);
    }
    bool isValidIP(const string& ip) {
        regex ipRegex("^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$");
        return regex_match(ip, ipRegex);
    }
    void getGeoIP(const string &ip) {
        if (!isValidIP(ip)) {
            string error = "Invalid IP address: " + ip;
            Logger::log(error, Logger::ERROR);
            cout << error << endl;
            return;
        }
        if (!curl) {
            string error = "CURL handle not initialized";
            Logger::log(error, Logger::ERROR);
            cout << error << endl;
            return;
        }
        string url = "http://ip-api.com/json/" + ip;
        string response;
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, [](char* ptr, size_t size, size_t nmemb, void* userdata) -> size_t {
            ((string*)userdata)->append(ptr, size * nmemb);
            return size * nmemb;
        });
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        CURLcode res = curl_easy_perform(curl);
        if (res == CURLE_OK) {
            Logger::log("Raw API response: " + response, Logger::INFO);
            try {
                json j = json::parse(response);
                if (j.contains("status") && j["status"] == "fail") {
                    string error = "GeoIP API error: " + j["message"].get<string>();
                    Logger::log(error, Logger::ERROR);
                    cout << error << endl;
                    return;
                }
                string country = j.contains("country") ? j["country"].get<string>() : "Unknown";
                string city = j.contains("city") ? j["city"].get<string>() : "Unknown";
                string message = "GeoIP for " + ip + ": Country=" + country + ", City=" + city;
                Logger::log(message, Logger::INFO);
                cout << message << endl;
                if (country == "North Korea" || country == "Iran") {
                    blockIPAddress(ip);
                }
            } catch (const exception& e) {
                string error = "GeoIP parse error: " + string(e.what());
                Logger::log(error, Logger::ERROR);
                cout << error << endl;
            }
        } else {
            string error = "GeoIP request failed: " + string(curl_easy_strerror(res));
            Logger::log(error, Logger::ERROR);
            cout << error << endl;
        }
        this_thread::sleep_for(chrono::milliseconds(1500));
    }
    void cleanupExpiredConnections() {
        auto now = chrono::system_clock::now();
        vector<vector<double>> tempInputs, tempLabels;
        lock_guard<mutex> lock(globalMutex);
        for (auto it = connectionTable.begin(); it != connectionTable.end(); ) {
            double timeDiff = chrono::duration<double>(now - it->second.lastUpdate).count();
            if (timeDiff > TIMEOUT_SECONDS) {
                NetworkFeatures f = extractFeatures(it->second);
                vector<double> input = convertToVector(f);
                vector<double> label = {it->second.wasBlocked ? 1.0 : 0.0};
                tempInputs.push_back(input);
                tempLabels.push_back(label);
                it = connectionTable.erase(it);
            } else {
                ++it;
            }
        }
        trainingData.insert(trainingData.end(), tempInputs.begin(), tempInputs.end());
        trainingLabels.insert(trainingLabels.end(), tempLabels.begin(), tempLabels.end());
        Logger::log("Cleaned " + to_string(tempInputs.size()) + " expired connections.", Logger::INFO);
    }
    bool addFirewallRule(const string &action, const string &direction, const string &source, const string &destination, const string &protocol) {
        string rule = "rule family=\"ipv4\" " + direction + " source address=\"" + source + "\" destination address=\"" + destination + "\" service name=\"" + protocol + "\" " + action;
        string cmd = "firewall-cmd --permanent --add-rich-rule='" + rule + "'";
        string output = executeSystemCommand(cmd);
        executeSystemCommand("firewall-cmd --reload");
        if (output.find("success") != string::npos) {
            Logger::log("Added firewall rule: " + rule, Logger::INFO);
            return true;
        } else {
            Logger::log("Failed to add rule: " + output, Logger::ERROR);
            return false;
        }
    }
    bool removeFirewallRule(const string &action, const string &direction, const string &source, const string &destination, const string &protocol) {
        string rule = "rule family=\"ipv4\" " + direction + " source address=\"" + source + "\" destination address=\"" + destination + "\" service name=\"" + protocol + "\" " + action;
        string cmd = "firewall-cmd --permanent --remove-rich-rule='" + rule + "'";
        string output = executeSystemCommand(cmd);
        executeSystemCommand("firewall-cmd --reload");
        if (output.find("success") != string::npos) {
            Logger::log("Removed firewall rule: " + rule, Logger::INFO);
            return true;
        } else {
            Logger::log("Failed to remove rule: " + output, Logger::ERROR);
            return false;
        }
    }
    void sendNotification(const string &title, const string &message) {
        string cmd = "notify-send \"" + title + "\" \"" + message + "\"";
        int status = system(cmd.c_str());
        if (status != 0) {
            Logger::log("Failed to send notification: " + title, Logger::WARNING);
        } else {
            Logger::log("Notification sent: " + title + " - " + message, Logger::INFO);
        }
    }
    void ruleViolationDetected(const string &rule, const string &violationDetail) {
        string msg = "Rule violation detected: " + rule + " - " + violationDetail;
        Logger::log(msg, Logger::WARNING);
        sendNotification("Firewall Violation", msg);
    }
    bool detectThreat() {
        lock_guard<mutex> lock(globalMutex);
        for (const auto& pair : connectionTable) {
            NetworkFeatures f = extractFeatures(pair.second);
            vector<double> input = convertToVector(f);
            neuralNetwork->forwardPropagate(input);
            if (neuralNetwork->detectThreat() || threatIntel.isThreatIP(pair.second.sourceIP)) {
                return true;
            }
        }
        return false;
    }
    void respondToThreat(const string &ip) {
        blockIPAddress(ip);
        sendNotification("Threat Detected", "Blocked suspicious IP: " + ip);
        ruleViolationDetected("Threat Response", "IP " + ip + " blocked.");
    }
    void trainAdaptiveModel(const vector<NetworkTrafficData> &trafficLogs) {
        vector<vector<double>> inputs, targets;
        for (const auto& log : trafficLogs) {
            ConnectionState conn;
            conn.sourceIP = log.sourceIP;
            conn.destIP = log.destIP;
            conn.packetCount = log.packetCount;
            conn.totalBytes = log.bytesTransferred;
            conn.lastUpdate = chrono::system_clock::now();
            conn.wasBlocked = false;
            NetworkFeatures f = extractFeatures(conn);
            inputs.push_back(convertToVector(f));
            targets.push_back({0.0});
        }
        neuralNetwork->train(inputs, targets, EPOCHS, LEARNING_RATE);
        if (detectThreat()) autoHeal();
    }
    void autoHeal() {
        if (detectThreat()) {
            togglePanicMode();
            this_thread::sleep_for(chrono::seconds(30));
            togglePanicMode();
            rollbackRules();
        }
    }
    void rollbackRules() {
        executeSystemCommand("firewall-cmd --reload");
        Logger::log("Firewall rules rolled back.", Logger::INFO);
        cout << "Firewall rules rolled back." << endl;
    }
    void checkFirewallHealth() {
        string output = executeSystemCommand("firewall-cmd --state");
        if (output.find("running") == string::npos) {
            executeSystemCommand("systemctl restart firewalld");
            Logger::log("Firewall service restarted.", Logger::WARNING);
            cout << "Firewall service restarted." << endl;
        } else {
            Logger::log("Firewall is healthy.", Logger::INFO);
            cout << "Firewall is healthy." << endl;
        }
    }
    void optimizeFirewallRules() {
        executeSystemCommand("firewall-cmd --permanent --remove-service=http");
        executeSystemCommand("firewall-cmd --reload");
        Logger::log("Firewall rules optimized.", Logger::INFO);
        cout << "Firewall rules optimized." << endl;
    }
    void threatMonitor() {
        while (running) {
            autoHeal();
            this_thread::sleep_for(chrono::milliseconds(THREAT_CHECK_INTERVAL_MS));
        }
    }
    void systemMaintenance() {
        while (running) {
            cleanupExpiredConnections();
            optimizeFirewallRules();
            checkFirewallHealth();
            Logger::rotateLogs();
            this_thread::sleep_for(chrono::milliseconds(MAINTENANCE_INTERVAL_MS));
        }
    }
    void processPacket(const string& sourceIP, const string& sourcePort, const string& destIP, const string& destPort, int size) {
        string key = sourceIP + ":" + sourcePort + "->" + destIP + ":" + destPort;
        lock_guard<mutex> lock(globalMutex);
        auto& count = ipConnectionCounts[sourceIP];
        count++;
        if (count > CONNECTION_THRESHOLD) {
            respondToThreat(sourceIP);
            return;
        }
        if (connectionTable.find(key) == connectionTable.end()) {
            connectionTable[key] = {"NEW", sourceIP, destIP, sourcePort, destPort, chrono::system_clock::now(), 1, size, false};
        } else {
            auto& conn = connectionTable[key];
            conn.packetCount++;
            conn.totalBytes += size;
            conn.lastUpdate = chrono::system_clock::now();
        }
        if (size > AVERAGE_PACKET_SIZE * PACKET_SIZE_MULTIPLIER) {
            Logger::log("Large packet anomaly from " + sourceIP, Logger::WARNING);
            respondToThreat(sourceIP);
        }
        NetworkFeatures f = extractFeatures(connectionTable[key]);
        vector<double> input = convertToVector(f);
        neuralNetwork->forwardPropagate(input);
        if (neuralNetwork->detectThreat()) {
            respondToThreat(sourceIP);
            connectionTable[key].wasBlocked = true;
        }
    }
    void blockWebsite(const string &website) {
        blockDomain(website);
    }
    void trainNeuralNetwork() {
        if (trainingData.size() > MAX_TRAINING_SAMPLES && trainingData.size() == trainingLabels.size()) {
            neuralNetwork->train(trainingData, trainingLabels, EPOCHS, LEARNING_RATE);
            trainingData.clear();
            trainingLabels.clear();
            neuralNetwork->saveModel(MODEL_FILE);
        } else {
            Logger::log("Insufficient samples for training: " + to_string(trainingData.size()), Logger::WARNING);
        }
    }
    void restoreDefaultConfig() {
        executeSystemCommand("firewall-cmd --complete-reload");
        blockedIPs.clear();
        blockedDomains.clear();
        saveBlockedIPs();
        saveBlockedDomains();
        Logger::log("Restored default firewall configuration.", Logger::INFO);
    }
    string getStatus() {
        stringstream ss;
        ss << "Panic mode: " << (panicModeEnabled ? "Enabled" : "Disabled") << endl;
        ss << "Internet: " << (internetStatus ? "Connected" : "Disconnected") << endl;
        ss << "VPN: " << (isVpnConnected() ? "Connected" : "Disconnected") << endl;
        ss << "Blocked IPs: " << blockedIPs.size() << endl;
        ss << "Blocked Domains: " << blockedDomains.size() << endl;
        return ss.str();
    }
    static char* completion_generator(const char* text, int state) {
        static int list_index, len;
        static vector<string> matches;
        static string current_cmd;
        if (!state) {
            list_index = 0;
            len = strlen(text);
            matches.clear();
            current_cmd = rl_line_buffer;
            size_t space_pos = current_cmd.find_last_of(" \t");
            if (space_pos != string::npos && space_pos < current_cmd.length() - 1) {
                current_cmd = current_cmd.substr(0, space_pos);
            } else {
                current_cmd.clear();
            }
            if (current_cmd.empty()) {
                static const char* commands[] = {
                    "block-ip", "unblock-ip", "panic", "check-internet", "geoip",
                    "block-website", "block-domain", "unblock-domain", "block-category", "unblock-category",
                    "train", "restore-default", "add-port", "remove-port",
                    "connect-vpn", "disconnect-vpn", "status", "export-blocked-ips", "add-nat",
                    "remove-nat", "block-all", "unblock-all", "send-notification",
                    "rule-violation", "detect-threat", "respond-threat", "train-adaptive",
                    "auto-heal", "rollback", "check-health", "optimize", "cleanup-connections",
                    "set-log-level", "rotate-logs", "log-message", "help", "exit", nullptr
                };
                for (int i = 0; commands[i]; ++i) {
                    if (strncmp(text, commands[i], len) == 0) {
                        matches.push_back(commands[i]);
                    }
                }
            } else {
                istringstream iss(current_cmd);
                string cmd;
                iss >> cmd;
                if (cmd == "block-ip" || cmd == "unblock-ip" || cmd == "geoip" || cmd == "respond-threat") {
                    if (blockedIPsPtr) {
                        for (const auto& ip : *blockedIPsPtr) {
                            if (strncmp(text, ip.c_str(), len) == 0) {
                                matches.push_back(ip);
                            }
                        }
                    }
                } else if (cmd == "block-domain" || cmd == "unblock-domain") {
                    if (blockedDomainsPtr) {
                        for (const auto& pair : *blockedDomainsPtr) {
                            if (strncmp(text, pair.first.c_str(), len) == 0) {
                                matches.push_back(pair.first);
                            }
                        }
                    }
                    static const char* sample_domains[] = {"espn.com", "nfl.com", "nba.com", "cbssports.com", nullptr};
                    for (int i = 0; sample_domains[i]; ++i) {
                        if (strncmp(text, sample_domains[i], len) == 0) {
                            matches.push_back(sample_domains[i]);
                        }
                    }
                } else if (cmd == "block-category" || cmd == "unblock-category") {
                    static const char* categories[] = {"sports", "news", "social", "gaming", nullptr};
                    for (int i = 0; categories[i]; ++i) {
                        if (strncmp(text, categories[i], len) == 0) {
                            matches.push_back(categories[i]);
                        }
                    }
                } else if (cmd == "add-port" || cmd == "remove-port") {
                    static const char* protocols[] = {"tcp", "udp", nullptr};
                    for (int i = 0; protocols[i]; ++i) {
                        if (strncmp(text, protocols[i], len) == 0) {
                            matches.push_back(protocols[i]);
                        }
                    }
                } else if (cmd == "set-log-level") {
                    static const char* levels[] = {"INFO", "WARNING", "ERROR", "DEBUG", nullptr};
                    for (int i = 0; levels[i]; ++i) {
                        if (strncmp(text, levels[i], len) == 0) {
                            matches.push_back(levels[i]);
                        }
                    }
                } else if (cmd == "help") {
                    static const char* categories[] = {
                        "block", "firewall", "network", "threat", "vpn", "logging", "status", nullptr
                    };
                    for (int i = 0; categories[i]; ++i) {
                        if (strncmp(text, categories[i], len) == 0) {
                            matches.push_back(categories[i]);
                        }
                    }
                }
            }
        }
        if (static_cast<size_t>(list_index) < matches.size()) {
            return strdup(matches[list_index++].c_str());
        }
        return nullptr;
    }
    static char** firewall_completion(const char* text, int start, int end) {
        (void)start; // Suppress unused parameter warning
        (void)end;   // Suppress unused parameter warning
        rl_attempted_completion_over = 1;
        return rl_completion_matches(text, completion_generator);
    }
    void runCLI() {
        if (!isatty(STDIN_FILENO)) {
            string command;
            while (running && getline(cin, command)) {
                if (command.empty()) continue;
                istringstream iss(command);
                string cmd;
                iss >> cmd;
                if (cmd == "exit") break;
                else if (cmd == "help") {
                    string category;
                    iss >> category;
                    cout << getHelpInformation(category) << endl;
                } else if (cmd == "block-ip") {
                    string ip;
                    iss >> ip;
                    if (ip.empty()) cout << "Usage: block-ip <ip>" << endl;
                    else blockIPAddress(ip);
                } else if (cmd == "unblock-ip") {
                    string ip;
                    iss >> ip;
                    if (ip.empty()) cout << "Usage: unblock-ip <ip>" << endl;
                    else unblockIPAddress(ip);
                } else if (cmd == "panic") {
                    togglePanicMode();
                } else if (cmd == "check-internet") {
                    checkInternetConnectivity();
                } else if (cmd == "geoip") {
                    string ip;
                    iss >> ip;
                    if (ip.empty()) cout << "Usage: geoip <ip>" << endl;
                    else getGeoIP(ip);
                } else if (cmd == "block-website") {
                    string site;
                    iss >> site;
                    if (site.empty()) cout << "Usage: block-website <domain>" << endl;
                    else blockWebsite(site);
                } else if (cmd == "block-domain") {
                    string domain, category;
                    iss >> domain >> category;
                    if (domain.empty()) cout << "Usage: block-domain <domain> [category]" << endl;
                    else blockDomain(domain, category);
                } else if (cmd == "unblock-domain") {
                    string domain;
                    iss >> domain;
                    if (domain.empty()) cout << "Usage: unblock-domain <domain>" << endl;
                    else unblockDomain(domain);
                } else if (cmd == "block-category") {
                    string category;
                    iss >> category;
                    if (category.empty()) cout << "Usage: block-category <category>" << endl;
                    else blockCategory(category);
                } else if (cmd == "unblock-category") {
                    string category;
                    iss >> category;
                    if (category.empty()) cout << "Usage: unblock-category <category>" << endl;
                    else unblockCategory(category);
                } else if (cmd == "train") {
                    trainNeuralNetwork();
                } else if (cmd == "restore-default") {
                    restoreDefaultConfig();
                } else if (cmd == "add-port") {
                    string port, protocol;
                    iss >> port >> protocol;
                    if (port.empty() || protocol.empty()) cout << "Usage: add-port <port> <protocol>" << endl;
                    else addFirewallRule("accept", "in", "0.0.0.0/0", port, protocol);
                } else if (cmd == "remove-port") {
                    string port, protocol;
                    iss >> port >> protocol;
                    if (port.empty() || protocol.empty()) cout << "Usage: remove-port <port> <protocol>" << endl;
                    else removeFirewallRule("accept", "in", "0.0.0.0/0", port, protocol);
                } else if (cmd == "connect-vpn") {
                    string config;
                    iss >> config;
                    if (config.empty()) cout << "Usage: connect-vpn <config_path>" << endl;
                    else connectToVpn(config);
                } else if (cmd == "disconnect-vpn") {
                    disconnectVpn();
                } else if (cmd == "status") {
                    cout << "Panic mode: " << (panicModeEnabled ? "Enabled" : "Disabled") << endl;
                    cout << "Internet: " << (internetStatus ? "Connected" : "Disconnected") << endl;
                    cout << "VPN: " << (isVpnConnected() ? "Connected" : "Disconnected") << endl;
                    cout << "Blocked IPs: " << blockedIPs.size() << endl;
                    cout << "Blocked Domains: " << blockedDomains.size() << endl;
                } else if (cmd == "export-blocked-ips") {
                    string filename;
                    iss >> filename;
                    if (filename.empty()) cout << "Usage: export-blocked-ips <filename>" << endl;
                    else exportBlockedIPsToCSV(filename);
                } else if (cmd == "add-nat") {
                    string sourceIP, destIP, port;
                    iss >> sourceIP >> destIP >> port;
                    if (sourceIP.empty() || destIP.empty() || port.empty()) cout << "Usage: add-nat <sourceIP> <destIP> <port>" << endl;
                    else addNatRule(sourceIP, destIP, port);
                } else if (cmd == "remove-nat") {
                    string ruleID;
                    getline(iss, ruleID);
                    ruleID.erase(0, ruleID.find_first_not_of(" \t"));
                    if (ruleID.empty()) cout << "Usage: remove-nat <ruleID>" << endl;
                    else removeNatRule(ruleID);
                } else if (cmd == "block-all") {
                    blockAllTraffic();
                } else if (cmd == "unblock-all") {
                    unblockAllTraffic();
                } else if (cmd == "send-notification") {
                    string title, message;
                    iss >> title;
                    getline(iss, message);
                    message.erase(0, message.find_first_not_of(" \t"));
                    if (title.empty() || message.empty()) cout << "Usage: send-notification <title> <message>" << endl;
                    else sendNotification(title, message);
                } else if (cmd == "rule-violation") {
                    string rule, detail;
                    iss >> rule;
                    getline(iss, detail);
                    detail.erase(0, detail.find_first_not_of(" \t"));
                    if (rule.empty() || detail.empty()) cout << "Usage: rule-violation <rule> <detail>" << endl;
                    else ruleViolationDetected(rule, detail);
                } else if (cmd == "detect-threat") {
                    cout << "Threat detected: " << (detectThreat() ? "Yes" : "No") << endl;
                } else if (cmd == "respond-threat") {
                    string ip;
                    iss >> ip;
                    if (ip.empty()) cout << "Usage: respond-threat <ip>" << endl;
                    else respondToThreat(ip);
                } else if (cmd == "train-adaptive") {
                    cout << "Training adaptive model requires traffic data (not implemented for manual input)." << endl;
                } else if (cmd == "auto-heal") {
                    autoHeal();
                } else if (cmd == "rollback") {
                    rollbackRules();
                } else if (cmd == "check-health") {
                    checkFirewallHealth();
                } else if (cmd == "optimize") {
                    optimizeFirewallRules();
                } else if (cmd == "cleanup-connections") {
                    cleanupExpiredConnections();
                } else if (cmd == "set-log-level") {
                    string level;
                    iss >> level;
                    if (level == "INFO") Logger::setLevel(Logger::INFO);
                    else if (level == "WARNING") Logger::setLevel(Logger::WARNING);
                    else if (level == "ERROR") Logger::setLevel(Logger::ERROR);
                    else if (level == "DEBUG") Logger::setLevel(Logger::DEBUG);
                    else cout << "Usage: set-log-level <INFO|WARNING|ERROR|DEBUG>" << endl;
                } else if (cmd == "rotate-logs") {
                    Logger::rotateLogs();
                } else if (cmd == "log-message") {
                    string level, message;
                    iss >> level;
                    getline(iss, message);
                    message.erase(0, message.find_first_not_of(" \t"));
                    if (level.empty() || message.empty()) cout << "Usage: log-message <INFO|WARNING|ERROR|DEBUG> <message>" << endl;
                    else {
                        if (level == "INFO") Logger::log(message, Logger::INFO);
                        else if (level == "WARNING") Logger::log(message, Logger::WARNING);
                        else if (level == "ERROR") Logger::log(message, Logger::ERROR);
                        else if (level == "DEBUG") Logger::log(message, Logger::DEBUG);
                        else cout << "Invalid log level." << endl;
                    }
                } else {
                    cout << "Unknown command. Type 'help' for list of categories." << endl;
                }
            }
            return;
        }
        rl_attempted_completion_function = firewall_completion;
        char* input;
        cout << "YUNA Firewall CLI - Type 'help' for commands." << endl;
        while (running && (input = readline("> "))) {
            if (!input) break;
            string command(input);
            free(input);
            if (command.empty()) continue;
            add_history(command.c_str());
            istringstream iss(command);
            string cmd;
            iss >> cmd;
            if (cmd == "exit") break;
            else if (cmd == "help") {
                string category;
                iss >> category;
                cout << getHelpInformation(category) << endl;
            } else if (cmd == "block-ip") {
                string ip;
                iss >> ip;
                if (ip.empty()) cout << "Usage: block-ip <ip>" << endl;
                else blockIPAddress(ip);
            } else if (cmd == "unblock-ip") {
                string ip;
                iss >> ip;
                if (ip.empty()) cout << "Usage: unblock-ip <ip>" << endl;
                else unblockIPAddress(ip);
            } else if (cmd == "panic") {
                togglePanicMode();
            } else if (cmd == "check-internet") {
                checkInternetConnectivity();
            } else if (cmd == "geoip") {
                string ip;
                iss >> ip;
                if (ip.empty()) cout << "Usage: geoip <ip>" << endl;
                else getGeoIP(ip);
            } else if (cmd == "block-website") {
                string site;
                iss >> site;
                if (site.empty()) cout << "Usage: block-website <domain>" << endl;
                else blockWebsite(site);
            } else if (cmd == "block-domain") {
                string domain, category;
                iss >> domain >> category;
                if (domain.empty()) cout << "Usage: block-domain <domain> [category]" << endl;
                else blockDomain(domain, category);
            } else if (cmd == "unblock-domain") {
                string domain;
                iss >> domain;
                if (domain.empty()) cout << "Usage: unblock-domain <domain>" << endl;
                else unblockDomain(domain);
            } else if (cmd == "block-category") {
                string category;
                iss >> category;
                if (category.empty()) cout << "Usage: block-category <category>" << endl;
                else blockCategory(category);
            } else if (cmd == "unblock-category") {
                string category;
                iss >> category;
                if (category.empty()) cout << "Usage: unblock-category <category>" << endl;
                else unblockCategory(category);
            } else if (cmd == "train") {
                trainNeuralNetwork();
            } else if (cmd == "restore-default") {
                restoreDefaultConfig();
            } else if (cmd == "add-port") {
                string port, protocol;
                iss >> port >> protocol;
                if (port.empty() || protocol.empty()) cout << "Usage: add-port <port> <protocol>" << endl;
                else addFirewallRule("accept", "in", "0.0.0.0/0", port, protocol);
            } else if (cmd == "remove-port") {
                string port, protocol;
                iss >> port >> protocol;
                if (port.empty() || protocol.empty()) cout << "Usage: remove-port <port> <protocol>" << endl;
                else removeFirewallRule("accept", "in", "0.0.0.0/0", port, protocol);
            } else if (cmd == "connect-vpn") {
                string config;
                iss >> config;
                if (config.empty()) cout << "Usage: connect-vpn <config_path>" << endl;
                else connectToVpn(config);
            } else if (cmd == "disconnect-vpn") {
                disconnectVpn();
            } else if (cmd == "status") {
                cout << "Panic mode: " << (panicModeEnabled ? "Enabled" : "Disabled") << endl;
                cout << "Internet: " << (internetStatus ? "Connected" : "Disconnected") << endl;
                cout << "VPN: " << (isVpnConnected() ? "Connected" : "Disconnected") << endl;
                cout << "Blocked IPs: " << blockedIPs.size() << endl;
                cout << "Blocked Domains: " << blockedDomains.size() << endl;
            } else if (cmd == "export-blocked-ips") {
                string filename;
                iss >> filename;
                if (filename.empty()) cout << "Usage: export-blocked-ips <filename>" << endl;
                else exportBlockedIPsToCSV(filename);
            } else if (cmd == "add-nat") {
                string sourceIP, destIP, port;
                iss >> sourceIP >> destIP >> port;
                if (sourceIP.empty() || destIP.empty() || port.empty()) cout << "Usage: add-nat <sourceIP> <destIP> <port>" << endl;
                else addNatRule(sourceIP, destIP, port);
            } else if (cmd == "remove-nat") {
                string ruleID;
                getline(iss, ruleID);
                ruleID.erase(0, ruleID.find_first_not_of(" \t"));
                if (ruleID.empty()) cout << "Usage: remove-nat <ruleID>" << endl;
                else removeNatRule(ruleID);
            } else if (cmd == "block-all") {
                blockAllTraffic();
            } else if (cmd == "unblock-all") {
                unblockAllTraffic();
            } else if (cmd == "send-notification") {
                string title, message;
                iss >> title;
                getline(iss, message);
                message.erase(0, message.find_first_not_of(" \t"));
                if (title.empty() || message.empty()) cout << "Usage: send-notification <title> <message>" << endl;
                else sendNotification(title, message);
            } else if (cmd == "rule-violation") {
                string rule, detail;
                iss >> rule;
                getline(iss, detail);
                detail.erase(0, detail.find_first_not_of(" \t"));
                if (rule.empty() || detail.empty()) cout << "Usage: rule-violation <rule> <detail>" << endl;
                else ruleViolationDetected(rule, detail);
            } else if (cmd == "detect-threat") {
                cout << "Threat detected: " << (detectThreat() ? "Yes" : "No") << endl;
            } else if (cmd == "respond-threat") {
                string ip;
                iss >> ip;
                if (ip.empty()) cout << "Usage: respond-threat <ip>" << endl;
                else respondToThreat(ip);
            } else if (cmd == "train-adaptive") {
                cout << "Training adaptive model requires traffic data (not implemented for manual input)." << endl;
            } else if (cmd == "auto-heal") {
                autoHeal();
            } else if (cmd == "rollback") {
                rollbackRules();
            } else if (cmd == "check-health") {
                checkFirewallHealth();
            } else if (cmd == "optimize") {
                optimizeFirewallRules();
            } else if (cmd == "cleanup-connections") {
                cleanupExpiredConnections();
            } else if (cmd == "set-log-level") {
                string level;
                iss >> level;
                if (level == "INFO") Logger::setLevel(Logger::INFO);
                else if (level == "WARNING") Logger::setLevel(Logger::WARNING);
                else if (level == "ERROR") Logger::setLevel(Logger::ERROR);
                else if (level == "DEBUG") Logger::setLevel(Logger::DEBUG);
                else cout << "Usage: set-log-level <INFO|WARNING|ERROR|DEBUG>" << endl;
            } else if (cmd == "rotate-logs") {
                Logger::rotateLogs();
            } else if (cmd == "log-message") {
                string level, message;
                iss >> level;
                getline(iss, message);
                message.erase(0, message.find_first_not_of(" \t"));
                if (level.empty() || message.empty()) cout << "Usage: log-message <INFO|WARNING|ERROR|DEBUG> <message>" << endl;
                else {
                    if (level == "INFO") Logger::log(message, Logger::INFO);
                    else if (level == "WARNING") Logger::log(message, Logger::WARNING);
                    else if (level == "ERROR") Logger::log(message, Logger::ERROR);
                    else if (level == "DEBUG") Logger::log(message, Logger::DEBUG);
                    else cout << "Invalid log level." << endl;
                }
            } else {
                cout << "Unknown command. Type 'help' for list of categories." << endl;
            }
            cout << "> ";
        }
        rl_free_line_state();
        rl_cleanup_after_signal();
    }
};
// PacketSniffer::packetCallback implementation
void PacketSniffer::packetCallback(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    FirewallManager* mgr = reinterpret_cast<FirewallManager*>(user);
    if (pkthdr->len < 34) return;
    const u_char* ipHeader = packet + 14;
    int ipHeaderLen = (*ipHeader & 0x0F) * 4;
    if (ipHeaderLen < 20) return;
    char srcBuf[INET_ADDRSTRLEN], dstBuf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, ipHeader + 12, srcBuf, sizeof(srcBuf));
    inet_ntop(AF_INET, ipHeader + 16, dstBuf, sizeof(dstBuf));
    string sourceIP = srcBuf;
    string destIP = dstBuf;
    u_char protocol = *(ipHeader + 9);
    string sourcePort = "0", destPort = "0";
    if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
        const u_char* transportHeader = ipHeader + ipHeaderLen;
        sourcePort = to_string(ntohs(*(uint16_t*)transportHeader));
        destPort = to_string(ntohs(*(uint16_t*)(transportHeader + 2)));
    }
    mgr->processPacket(sourceIP, sourcePort, destIP, destPort, pkthdr->len);
}
// Help information
string getHelpInformation(const string& category) {
    if (category.empty()) {
        string help = "YUNA Firewall CLI Help Menu\n\n";
        help += "Available categories (use 'help <category>' to view commands):\n\n";
        help += "block - Commands for blocking and unblocking IPs/websites\n";
        help += "firewall - Commands for managing firewall rules\n";
        help += "network - Commands for network status and maintenance\n";
        help += "threat - Commands for threat detection and response\n";
        help += "vpn - Commands for VPN connections\n";
        help += "logging - Commands for logging and notifications\n";
        help += "status - Commands for system status and exports\n\n";
        help += "exit - Quit the CLI\n";
        return help;
    }
    string help = "YUNA Firewall CLI Commands - " + category + "\n\n";
    if (category == "block") {
        help += "block-ip <ip> - Block an IP address\n\n";
        help += "unblock-ip <ip> - Unblock an IP address\n\n";
        help += "block-website <domain> - Block a website by resolving to IP\n\n";
        help += "block-domain <domain> [category] - Block a domain with optional category\n\n";
        help += "unblock-domain <domain> - Unblock a domain\n\n";
        help += "block-category <category> - Block all domains in a category (e.g., sports)\n\n";
        help += "unblock-category <category> - Unblock all domains in a category\n\n";
        help += "block-all - Block all traffic\n\n";
        help += "unblock-all - Unblock all traffic\n\n";
    } else if (category == "firewall") {
        help += "add-port <port> <protocol> - Add a port rule (e.g., 80 tcp)\n\n";
        help += "remove-port <port> <protocol> - Remove a port rule\n\n";
        help += "add-nat <sourceIP> <destIP> <port> - Add a NAT rule\n\n";
        help += "remove-nat <ruleID> - Remove a NAT rule\n\n";
        help += "optimize - Optimize firewall rules\n\n";
        help += "rollback - Roll back firewall rules\n\n";
        help += "restore-default - Restore default firewall configuration\n\n";
    } else if (category == "network") {
        help += "check-internet - Check internet connectivity\n\n";
        help += "check-health - Check firewall service health\n\n";
        help += "geoip <ip> - Get geographical information for an IP\n\n";
        help += "cleanup-connections - Clean up expired connections\n\n";
    } else if (category == "threat") {
        help += "detect-threat - Check if a threat is detected\n\n";
        help += "respond-threat <ip> - Respond to a threat by blocking an IP\n\n";
        help += "train - Train the neural network with collected data\n\n";
        help += "train-adaptive - Train adaptive model (not implemented for manual input)\n\n";
        help += "auto-heal - Trigger auto-heal process\n\n";
    } else if (category == "vpn") {
        help += "connect-vpn <config_path> - Connect to VPN\n\n";
        help += "disconnect-vpn - Disconnect from VPN\n\n";
    } else if (category == "logging") {
        help += "send-notification <title> <message> - Send a desktop notification\n\n";
        help += "rule-violation <rule> <detail> - Report a rule violation\n\n";
        help += "set-log-level <INFO|WARNING|ERROR|DEBUG> - Set logging level\n\n";
        help += "rotate-logs - Rotate log files\n\n";
        help += "log-message <INFO|WARNING|ERROR|DEBUG> <message> - Log a custom message\n\n";
    } else if (category == "status") {
        help += "status - Show current system status\n\n";
        help += "export-blocked-ips <filename> - Export blocked IPs to a CSV file\n\n";
    } else {
        help = "Unknown category: " + category + "\n\nUse 'help' to see available categories.\n";
    }
    return help;
}
// Banner display
void displayBanner() {
    cout << R"(
    ██╗ ██╗██╗ ██╗███╗ ██╗ █████╗
    ╚██╗ ██╔╝██║ ██║████╗ ██║██╔══██╗
     ╚████╔╝ ██║ ██║██╔██╗ ██║███████║
      ╚██╔╝ ██║ ██║██║╚██╗██║██╔══██║
       ██║ ╚██████╔╝██║ ╚████║██║ ██║
       ╚═╝ ╚═════╝ ╚═╝ ╚═══╝╚═╝ ╚═╝
        Firewall Management System
    )" << endl;
}
// GUI Stream Buffer for redirecting cout to QTextEdit
class TextEditStream : public std::basic_streambuf<char> {
private:
    QTextEdit* textEdit;
public:
    TextEditStream(QTextEdit* te) : textEdit(te) {}
protected:
    virtual std::streamsize xsputn(const char *s, std::streamsize n) {
        textEdit->append(QString::fromUtf8(s, static_cast<int>(n)));
        return n;
    }
    virtual int overflow(int c) {
        if (c != EOF) {
            textEdit->append(QString(static_cast<char>(c)));
        }
        return c;
    }
};
// GUI Main Window
class GUIMainWindow : public QMainWindow {
Q_OBJECT
private:
    FirewallManager* manager;
    QTextEdit* statusText;
    TextEditStream* coutStream;
    std::streambuf* oldCoutBuf;
public:
    GUIMainWindow(FirewallManager* mgr, QWidget *parent = nullptr) : QMainWindow(parent), manager(mgr) {
        setWindowTitle("YUNA Firewall Manager");
        setMinimumSize(800, 600);

        statusText = new QTextEdit(this);
        statusText->setReadOnly(true);
        coutStream = new TextEditStream(statusText);
        oldCoutBuf = std::cout.rdbuf(coutStream);

        QTabWidget *tabs = new QTabWidget(this);

        tabs->addTab(createBlockTab(), "Block");
        tabs->addTab(createFirewallTab(), "Firewall");
        tabs->addTab(createNetworkTab(), "Network");
        tabs->addTab(createThreatTab(), "Threat");
        tabs->addTab(createVpnTab(), "VPN");
        tabs->addTab(createLoggingTab(), "Logging");
        tabs->addTab(createStatusTab(), "Status");

        QVBoxLayout *mainLayout = new QVBoxLayout;
        mainLayout->addWidget(tabs);
        mainLayout->addWidget(new QLabel("Status Output:"));
        mainLayout->addWidget(statusText);

        QWidget *central = new QWidget;
        central->setLayout(mainLayout);
        setCentralWidget(central);
    }
    ~GUIMainWindow() {
        std::cout.rdbuf(oldCoutBuf);
        delete coutStream;
    }
private:
    QWidget* createBlockTab() {
        QWidget *tab = new QWidget;
        QGridLayout *layout = new QGridLayout;
        int row = 0;

        // Block/Unblock IP
        QLabel *ipLabel = new QLabel("IP Address:");
        QLineEdit *ipInput = new QLineEdit;
        QPushButton *blockIpBtn = new QPushButton("Block IP");
        connect(blockIpBtn, &QPushButton::clicked, [this, ipInput]() {
            string ip = ipInput->text().toStdString();
            if (!ip.empty()) {
                manager->blockIPAddress(ip);
            } else {
                statusText->append("Error: Enter an IP address.");
            }
        });
        QPushButton *unblockIpBtn = new QPushButton("Unblock IP");
        connect(unblockIpBtn, &QPushButton::clicked, [this, ipInput]() {
            string ip = ipInput->text().toStdString();
            if (!ip.empty()) {
                manager->unblockIPAddress(ip);
            } else {
                statusText->append("Error: Enter an IP address.");
            }
        });
        layout->addWidget(ipLabel, row, 0);
        layout->addWidget(ipInput, row, 1);
        layout->addWidget(blockIpBtn, row, 2);
        layout->addWidget(unblockIpBtn, row, 3);
        row++;

        // Block Website
        QLabel *websiteLabel = new QLabel("Website Domain:");
        QLineEdit *websiteInput = new QLineEdit;
        QPushButton *blockWebsiteBtn = new QPushButton("Block Website");
        connect(blockWebsiteBtn, &QPushButton::clicked, [this, websiteInput]() {
            string site = websiteInput->text().toStdString();
            if (!site.empty()) {
                manager->blockWebsite(site);
            } else {
                statusText->append("Error: Enter a website domain.");
            }
        });
        layout->addWidget(websiteLabel, row, 0);
        layout->addWidget(websiteInput, row, 1);
        layout->addWidget(blockWebsiteBtn, row, 2);
        row++;

        // Block/Unblock Domain
        QLabel *domainLabel = new QLabel("Domain:");
        QLineEdit *domainInput = new QLineEdit;
        QLabel *catLabel = new QLabel("Category (optional):");
        QLineEdit *catInput = new QLineEdit;
        QPushButton *blockDomainBtn = new QPushButton("Block Domain");
        connect(blockDomainBtn, &QPushButton::clicked, [this, domainInput, catInput]() {
            string domain = domainInput->text().toStdString();
            string cat = catInput->text().toStdString();
            if (!domain.empty()) {
                manager->blockDomain(domain, cat);
            } else {
                statusText->append("Error: Enter a domain.");
            }
        });
        QPushButton *unblockDomainBtn = new QPushButton("Unblock Domain");
        connect(unblockDomainBtn, &QPushButton::clicked, [this, domainInput]() {
            string domain = domainInput->text().toStdString();
            if (!domain.empty()) {
                manager->unblockDomain(domain);
            } else {
                statusText->append("Error: Enter a domain.");
            }
        });
        layout->addWidget(domainLabel, row, 0);
        layout->addWidget(domainInput, row, 1);
        layout->addWidget(blockDomainBtn, row, 2);
        layout->addWidget(unblockDomainBtn, row, 3);
        row++;
        layout->addWidget(catLabel, row, 0);
        layout->addWidget(catInput, row, 1);
        row++;

        // Block/Unblock Category
        QLabel *categoryLabel = new QLabel("Category:");
        QComboBox *categoryCombo = new QComboBox;
        categoryCombo->addItems({"sports", "news", "technology", "entertainment", "finance", "health", "travel", "education", "lifestyle", "science", "gaming", "food", "fashion"});
        QPushButton *blockCatBtn = new QPushButton("Block Category");
        connect(blockCatBtn, &QPushButton::clicked, [this, categoryCombo]() {
            string cat = categoryCombo->currentText().toStdString();
            manager->blockCategory(cat);
        });
        QPushButton *unblockCatBtn = new QPushButton("Unblock Category");
        connect(unblockCatBtn, &QPushButton::clicked, [this, categoryCombo]() {
            string cat = categoryCombo->currentText().toStdString();
            manager->unblockCategory(cat);
        });
        layout->addWidget(categoryLabel, row, 0);
        layout->addWidget(categoryCombo, row, 1);
        layout->addWidget(blockCatBtn, row, 2);
        layout->addWidget(unblockCatBtn, row, 3);
        row++;

        // Block/Unblock All Traffic
        QPushButton *blockAllBtn = new QPushButton("Block All Traffic");
        connect(blockAllBtn, &QPushButton::clicked, [this]() {
            manager->blockAllTraffic();
        });
        QPushButton *unblockAllBtn = new QPushButton("Unblock All Traffic");
        connect(unblockAllBtn, &QPushButton::clicked, [this]() {
            manager->unblockAllTraffic();
        });
        layout->addWidget(blockAllBtn, row, 0, 1, 2);
        layout->addWidget(unblockAllBtn, row, 2, 1, 2);

        tab->setLayout(layout);
        return tab;
    }

    QWidget* createFirewallTab() {
        QWidget *tab = new QWidget;
        QGridLayout *layout = new QGridLayout;
        int row = 0;

        // Add/Remove Port
        QLabel *portLabel = new QLabel("Port:");
        QLineEdit *portInput = new QLineEdit;
        QLabel *protoLabel = new QLabel("Protocol:");
        QComboBox *protoCombo = new QComboBox;
        protoCombo->addItems({"tcp", "udp"});
        QPushButton *addPortBtn = new QPushButton("Add Port");
        connect(addPortBtn, &QPushButton::clicked, [this, portInput, protoCombo]() {
            string port = portInput->text().toStdString();
            string proto = protoCombo->currentText().toStdString();
            if (!port.empty()) {
                manager->addFirewallRule("accept", "in", "0.0.0.0/0", port, proto);
            } else {
                statusText->append("Error: Enter a port.");
            }
        });
        QPushButton *removePortBtn = new QPushButton("Remove Port");
        connect(removePortBtn, &QPushButton::clicked, [this, portInput, protoCombo]() {
            string port = portInput->text().toStdString();
            string proto = protoCombo->currentText().toStdString();
            if (!port.empty()) {
                manager->removeFirewallRule("accept", "in", "0.0.0.0/0", port, proto);
            } else {
                statusText->append("Error: Enter a port.");
            }
        });
        layout->addWidget(portLabel, row, 0);
        layout->addWidget(portInput, row, 1);
        layout->addWidget(protoLabel, row, 2);
        layout->addWidget(protoCombo, row, 3);
        row++;
        layout->addWidget(addPortBtn, row, 0, 1, 2);
        layout->addWidget(removePortBtn, row, 2, 1, 2);
        row++;

        // Add NAT
        QLabel *srcIpLabel = new QLabel("Source IP:");
        QLineEdit *srcIpInput = new QLineEdit;
        QLabel *destIpLabel = new QLabel("Destination IP:");
        QLineEdit *destIpInput = new QLineEdit;
        QLabel *natPortLabel = new QLabel("Port:");
        QLineEdit *natPortInput = new QLineEdit;
        QPushButton *addNatBtn = new QPushButton("Add NAT Rule");
        connect(addNatBtn, &QPushButton::clicked, [this, srcIpInput, destIpInput, natPortInput]() {
            string src = srcIpInput->text().toStdString();
            string dest = destIpInput->text().toStdString();
            string port = natPortInput->text().toStdString();
            if (!src.empty() && !dest.empty() && !port.empty()) {
                manager->addNatRule(src, dest, port);
            } else {
                statusText->append("Error: Fill all fields for NAT.");
            }
        });
        layout->addWidget(srcIpLabel, row, 0);
        layout->addWidget(srcIpInput, row, 1);
        row++;
        layout->addWidget(destIpLabel, row, 0);
        layout->addWidget(destIpInput, row, 1);
        row++;
        layout->addWidget(natPortLabel, row, 0);
        layout->addWidget(natPortInput, row, 1);
        layout->addWidget(addNatBtn, row, 2);
        row++;

        // Remove NAT
        QLabel *ruleIdLabel = new QLabel("Rule ID:");
        QLineEdit *ruleIdInput = new QLineEdit;
        QPushButton *removeNatBtn = new QPushButton("Remove NAT Rule");
        connect(removeNatBtn, &QPushButton::clicked, [this, ruleIdInput]() {
            string ruleId = ruleIdInput->text().toStdString();
            if (!ruleId.empty()) {
                manager->removeNatRule(ruleId);
            } else {
                statusText->append("Error: Enter rule ID.");
            }
        });
        layout->addWidget(ruleIdLabel, row, 0);
        layout->addWidget(ruleIdInput, row, 1);
        layout->addWidget(removeNatBtn, row, 2);
        row++;

        // Other buttons
        QPushButton *optimizeBtn = new QPushButton("Optimize Rules");
        connect(optimizeBtn, &QPushButton::clicked, [this]() {
            manager->optimizeFirewallRules();
        });
        QPushButton *rollbackBtn = new QPushButton("Rollback Rules");
        connect(rollbackBtn, &QPushButton::clicked, [this]() {
            manager->rollbackRules();
        });
        QPushButton *restoreBtn = new QPushButton("Restore Default");
        connect(restoreBtn, &QPushButton::clicked, [this]() {
            manager->restoreDefaultConfig();
        });
        layout->addWidget(optimizeBtn, row, 0);
        layout->addWidget(rollbackBtn, row, 1);
        layout->addWidget(restoreBtn, row, 2);

        tab->setLayout(layout);
        return tab;
    }

    QWidget* createNetworkTab() {
        QWidget *tab = new QWidget;
        QVBoxLayout *layout = new QVBoxLayout;

        QPushButton *checkInternetBtn = new QPushButton("Check Internet Connectivity");
        connect(checkInternetBtn, &QPushButton::clicked, [this]() {
            manager->checkInternetConnectivity();
        });
        layout->addWidget(checkInternetBtn);

        QPushButton *checkHealthBtn = new QPushButton("Check Firewall Health");
        connect(checkHealthBtn, &QPushButton::clicked, [this]() {
            manager->checkFirewallHealth();
        });
        layout->addWidget(checkHealthBtn);

        QHBoxLayout *geoIpLayout = new QHBoxLayout;
        QLabel *geoIpLabel = new QLabel("IP for GeoIP:");
        QLineEdit *geoIpInput = new QLineEdit;
        QPushButton *geoIpBtn = new QPushButton("Get GeoIP");
        connect(geoIpBtn, &QPushButton::clicked, [this, geoIpInput]() {
            string ip = geoIpInput->text().toStdString();
            if (!ip.empty()) {
                manager->getGeoIP(ip);
            } else {
                statusText->append("Error: Enter an IP.");
            }
        });
        geoIpLayout->addWidget(geoIpLabel);
        geoIpLayout->addWidget(geoIpInput);
        geoIpLayout->addWidget(geoIpBtn);
        layout->addLayout(geoIpLayout);

        QPushButton *cleanupBtn = new QPushButton("Cleanup Expired Connections");
        connect(cleanupBtn, &QPushButton::clicked, [this]() {
            manager->cleanupExpiredConnections();
        });
        layout->addWidget(cleanupBtn);

        tab->setLayout(layout);
        return tab;
    }

    QWidget* createThreatTab() {
        QWidget *tab = new QWidget;
        QVBoxLayout *layout = new QVBoxLayout;

        QPushButton *detectThreatBtn = new QPushButton("Detect Threat");
        connect(detectThreatBtn, &QPushButton::clicked, [this]() {
            bool threat = manager->detectThreat();
            statusText->append("Threat detected: " + QString(threat ? "Yes" : "No"));
        });
        layout->addWidget(detectThreatBtn);

        QHBoxLayout *respondLayout = new QHBoxLayout;
        QLabel *respondIpLabel = new QLabel("IP to Respond:");
        QLineEdit *respondIpInput = new QLineEdit;
        QPushButton *respondThreatBtn = new QPushButton("Respond to Threat");
        connect(respondThreatBtn, &QPushButton::clicked, [this, respondIpInput]() {
            string ip = respondIpInput->text().toStdString();
            if (!ip.empty()) {
                manager->respondToThreat(ip);
            } else {
                statusText->append("Error: Enter an IP.");
            }
        });
        respondLayout->addWidget(respondIpLabel);
        respondLayout->addWidget(respondIpInput);
        respondLayout->addWidget(respondThreatBtn);
        layout->addLayout(respondLayout);

        QPushButton *trainBtn = new QPushButton("Train Neural Network");
        connect(trainBtn, &QPushButton::clicked, [this]() {
            manager->trainNeuralNetwork();
        });
        layout->addWidget(trainBtn);

        QPushButton *autoHealBtn = new QPushButton("Auto Heal");
        connect(autoHealBtn, &QPushButton::clicked, [this]() {
            manager->autoHeal();
        });
        layout->addWidget(autoHealBtn);

        tab->setLayout(layout);
        return tab;
    }

    QWidget* createVpnTab() {
        QWidget *tab = new QWidget;
        QVBoxLayout *layout = new QVBoxLayout;

        QHBoxLayout *connectLayout = new QHBoxLayout;
        QLabel *configLabel = new QLabel("VPN Config Path:");
        QLineEdit *configInput = new QLineEdit;
        QPushButton *browseBtn = new QPushButton("Browse");
        connect(browseBtn, &QPushButton::clicked, [configInput]() {
            QString file = QFileDialog::getOpenFileName(nullptr, "Select VPN Config", "", "Config Files (*.ovpn)");
            if (!file.isEmpty()) {
                configInput->setText(file);
            }
        });
        QPushButton *connectVpnBtn = new QPushButton("Connect VPN");
        connect(connectVpnBtn, &QPushButton::clicked, [this, configInput]() {
            string config = configInput->text().toStdString();
            if (!config.empty()) {
                manager->connectToVpn(config);
            } else {
                statusText->append("Error: Enter config path.");
            }
        });
        connectLayout->addWidget(configLabel);
        connectLayout->addWidget(configInput);
        connectLayout->addWidget(browseBtn);
        connectLayout->addWidget(connectVpnBtn);
        layout->addLayout(connectLayout);

        QPushButton *disconnectVpnBtn = new QPushButton("Disconnect VPN");
        connect(disconnectVpnBtn, &QPushButton::clicked, [this]() {
            manager->disconnectVpn();
        });
        layout->addWidget(disconnectVpnBtn);

        tab->setLayout(layout);
        return tab;
    }

    QWidget* createLoggingTab() {
        QWidget *tab = new QWidget;
        QGridLayout *layout = new QGridLayout;
        int row = 0;

        // Send Notification
        QLabel *titleLabel = new QLabel("Title:");
        QLineEdit *titleInput = new QLineEdit;
        QLabel *msgLabel = new QLabel("Message:");
        QLineEdit *msgInput = new QLineEdit;
        QPushButton *sendNotifBtn = new QPushButton("Send Notification");
        connect(sendNotifBtn, &QPushButton::clicked, [this, titleInput, msgInput]() {
            string title = titleInput->text().toStdString();
            string msg = msgInput->text().toStdString();
            if (!title.empty() && !msg.empty()) {
                manager->sendNotification(title, msg);
            } else {
                statusText->append("Error: Fill title and message.");
            }
        });
        layout->addWidget(titleLabel, row, 0);
        layout->addWidget(titleInput, row, 1);
        row++;
        layout->addWidget(msgLabel, row, 0);
        layout->addWidget(msgInput, row, 1);
        layout->addWidget(sendNotifBtn, row, 2);
        row++;

        // Rule Violation
        QLabel *ruleLabel = new QLabel("Rule:");
        QLineEdit *ruleInput = new QLineEdit;
        QLabel *detailLabel = new QLabel("Detail:");
        QLineEdit *detailInput = new QLineEdit;
        QPushButton *violationBtn = new QPushButton("Report Violation");
        connect(violationBtn, &QPushButton::clicked, [this, ruleInput, detailInput]() {
            string rule = ruleInput->text().toStdString();
            string detail = detailInput->text().toStdString();
            if (!rule.empty() && !detail.empty()) {
                manager->ruleViolationDetected(rule, detail);
            } else {
                statusText->append("Error: Fill rule and detail.");
            }
        });
        layout->addWidget(ruleLabel, row, 0);
        layout->addWidget(ruleInput, row, 1);
        row++;
        layout->addWidget(detailLabel, row, 0);
        layout->addWidget(detailInput, row, 1);
        layout->addWidget(violationBtn, row, 2);
        row++;

        // Set Log Level
        QLabel *logLevelLabel = new QLabel("Log Level:");
        QComboBox *logLevelCombo = new QComboBox;
        logLevelCombo->addItems({"INFO", "WARNING", "ERROR", "DEBUG"});
        QPushButton *setLogLevelBtn = new QPushButton("Set Log Level");
        connect(setLogLevelBtn, &QPushButton::clicked, [logLevelCombo]() {
            string level = logLevelCombo->currentText().toStdString();
            if (level == "INFO") Logger::setLevel(Logger::INFO);
            else if (level == "WARNING") Logger::setLevel(Logger::WARNING);
            else if (level == "ERROR") Logger::setLevel(Logger::ERROR);
            else if (level == "DEBUG") Logger::setLevel(Logger::DEBUG);
        });
        layout->addWidget(logLevelLabel, row, 0);
        layout->addWidget(logLevelCombo, row, 1);
        layout->addWidget(setLogLevelBtn, row, 2);
        row++;

        // Rotate Logs
        QPushButton *rotateLogsBtn = new QPushButton("Rotate Logs");
        connect(rotateLogsBtn, &QPushButton::clicked, []() {
            Logger::rotateLogs();
        });
        layout->addWidget(rotateLogsBtn, row, 0);

        // Log Message
        QLabel *customLevelLabel = new QLabel("Level:");
        QComboBox *customLevelCombo = new QComboBox;
        customLevelCombo->addItems({"INFO", "WARNING", "ERROR", "DEBUG"});
        QLabel *customMsgLabel = new QLabel("Message:");
        QLineEdit *customMsgInput = new QLineEdit;
        QPushButton *logMsgBtn = new QPushButton("Log Message");
        connect(logMsgBtn, &QPushButton::clicked, [customLevelCombo, customMsgInput]() {
            string level = customLevelCombo->currentText().toStdString();
            string msg = customMsgInput->text().toStdString();
            if (!msg.empty()) {
                if (level == "INFO") Logger::log(msg, Logger::INFO);
                else if (level == "WARNING") Logger::log(msg, Logger::WARNING);
                else if (level == "ERROR") Logger::log(msg, Logger::ERROR);
                else if (level == "DEBUG") Logger::log(msg, Logger::DEBUG);
            }
        });
        layout->addWidget(customLevelLabel, row, 1);
        layout->addWidget(customLevelCombo, row, 2);
        row++;
        layout->addWidget(customMsgLabel, row, 0);
        layout->addWidget(customMsgInput, row, 1);
        layout->addWidget(logMsgBtn, row, 2);

        tab->setLayout(layout);
        return tab;
    }

    QWidget* createStatusTab() {
        QWidget *tab = new QWidget;
        QVBoxLayout *layout = new QVBoxLayout;

        QPushButton *showStatusBtn = new QPushButton("Show Status");
        connect(showStatusBtn, &QPushButton::clicked, [this]() {
            string status = manager->getStatus();
            statusText->append(QString::fromStdString(status));
        });
        layout->addWidget(showStatusBtn);

        QHBoxLayout *exportLayout = new QHBoxLayout;
        QLabel *exportLabel = new QLabel("Export Filename:");
        QLineEdit *exportInput = new QLineEdit;
        QPushButton *exportBtn = new QPushButton("Export Blocked IPs");
        connect(exportBtn, &QPushButton::clicked, [this, exportInput]() {
            string filename = exportInput->text().toStdString();
            if (!filename.empty()) {
                manager->exportBlockedIPsToCSV(filename);
            } else {
                statusText->append("Error: Enter filename.");
            }
        });
        exportLayout->addWidget(exportLabel);
        exportLayout->addWidget(exportInput);
        exportLayout->addWidget(exportBtn);
        layout->addLayout(exportLayout);

        tab->setLayout(layout);
        return tab;
    }
};
// Main function
int main(int argc, char* argv[]) {
    signal(SIGINT, signalHandler);
    displayBanner();
    Logger::setLevel(Logger::DEBUG);
    Logger::startAsyncLogger();
    Logger::rotateLogs();
    string interface = (argc > 1) ? argv[1] : "eth0";
    FirewallManager manager(interface);
    int exitCode = 0;
    if (argc > 2 && string(argv[2]) == "gui") {
        QApplication app(argc, argv);
        GUIMainWindow window(&manager);
        window.show();
        exitCode = app.exec();
    } else {
        manager.runCLI();
    }
    Logger::shutdownAsyncLogger();
    return exitCode;
}
```