//AlSch092 @ Github
#pragma once
#include <iostream>
#include <fstream>
#include <string>
#include <ctime>
#include <cstdarg>
#include <mutex>

class Logger 
{
public:

    static void log(const std::string filename, const std::string& message) 
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
            std::time_t now = std::time(nullptr);
            char timestamp[64];
            std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", std::localtime(&now));
            logFile << "[" << timestamp << "] " << message << std::endl;
            if (logFile.fail()) 
            {
                std::cerr << "Error: Failed to write to log file." << std::endl;
            }
            logFile.flush();
        }
        else 
        {
            std::cerr << "Error: Log file is not open." << std::endl;
        }

        printf("%s\n", message.c_str());
        logFile.close();
    }

    template<typename... Args>
    static void logf(const char* filename, const char* format, Args... args)
    {
        char buffer[256];
        int ret = std::snprintf(buffer, sizeof(buffer), format, args...);
        if (ret >= 0 && ret < sizeof(buffer)) 
        {
            log(filename, std::string(buffer));
        }
        else 
        {
            std::cerr << "Error: Failed to format log message." << std::endl;
        }
    }

};