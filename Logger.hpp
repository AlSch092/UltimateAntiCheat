//AlSch092 @ Github
#pragma once
#include <iostream>
#include <fstream>
#include <string>
#include <ctime>
#include <cstdarg>
#include <mutex>

enum LogType
{
    Info,
    Warning,
    Err,
    Detection,
};

class Logger 
{
public:

    static void log(const std::string filename, LogType type, const std::string& message)
    {
        std::ofstream logFile;

        logFile.open(filename.c_str(), std::ios::out | std::ios::app);
        if (!logFile.is_open()) 
        {
            std::cerr << "Error: Could not open log file: " <<  "UltimateAnticheat.log" << std::endl;
            return;
        }

        if (logFile.is_open()) 
        {
            std::string msg_with_errorcode;

            switch (type)
            {
            case Err:
                msg_with_errorcode = "[ERROR] ";
                break;
            case Detection:
                msg_with_errorcode = "[DETECTION] ";
                break;
            case Info:
                msg_with_errorcode = "[INFO] ";
                break;
            case Warning:
                msg_with_errorcode = "[WARNING] ";
                break;

            default:
                msg_with_errorcode = "[ERROR] ";
                break;
            }

            msg_with_errorcode = msg_with_errorcode + message;

            std::time_t now = std::time(nullptr);
            char timestamp[64];
            std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", std::localtime(&now));
            logFile << "[" << timestamp << "] " << message << std::endl;

            if (logFile.fail()) 
            {
                std::cerr << "[ERROR] Failed to write to log file." << std::endl;
            }

            logFile.flush();
        }
        else 
        {
            std::cerr << "[ERROR] Log file is not open." << std::endl;
        }

        printf("%s\n", message.c_str());
        logFile.close();
    }

    template<typename... Args>
    static void logf(const char* filename, LogType type, const char* format, Args... args)
    {
        char buffer[512] = { 0 };
        int ret = std::snprintf(buffer, sizeof(buffer), format, args...);
        if (ret >= 0 && ret < sizeof(buffer)) 
        {
            log(filename, type, std::string(buffer));
        }
        else 
        {
            std::cerr << "Error: Failed to format log message." << std::endl;
        }
    }
};