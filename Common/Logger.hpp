//AlSch092 @ Github
#pragma once
#include <iostream>
#include <fstream>
#include <string>
#include <ctime>
#include <cstdarg>
#include <windows.h>
#include <mutex>
#include <map>

enum LogType
{
    Info, Warning, Err, Detection
};

const WORD ConsoleTextColors[] = 
{
    FOREGROUND_RED | FOREGROUND_INTENSITY,                       //red
    FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY,    //yellow
    FOREGROUND_GREEN | FOREGROUND_INTENSITY,                     //green
    FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY,   //cyan
    FOREGROUND_BLUE | FOREGROUND_INTENSITY,                      //blue
    FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY,     //magenta
    FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE,         // white 
};

class Logger final
{
public:
    static std::string logFileName;
    static bool enableLogging;

    static int getLogColor(LogType type) {
        const std::map<LogType, int> logColors = {
            { LogType::Detection,  ConsoleTextColors[0]},
            { LogType::Info, ConsoleTextColors[3] },
            { LogType::Err, ConsoleTextColors[5] },
            { LogType::Warning, FOREGROUND_GREEN }
        };
        return logColors.at(type);
    }

    static void logToFile(std::string& message) 
    {
        if (logFileName.empty()) 
        {
            return;
        }
        
        std::ofstream logFile(logFileName, std::ios::out | std::ios::app);

        if (!logFile.is_open())
        {
            std::cerr << "Error: Could not open log file: " << logFileName << std::endl;
            return;
        }

        std::time_t now = std::time(nullptr);
        char timestamp[20];
        std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", std::localtime(&now));

        logFile << "[" << timestamp << "] " << message << std::endl;

        if (logFile.fail())
        {
            std::cerr << "[ERROR] Failed to write to log file: " << logFileName << std::endl;
            return;
        }

        logFile.close(); // Close the file after writing
    }

    static void log(LogType type, const std::string& message)
    {
        if (!enableLogging) 
        {
            return;
        }

        std::lock_guard<std::mutex> lock(consoleMutex);

        std::string msg_with_errorcode;

        const std::map<LogType, const std::string> msgsTypes = 
        {
            { LogType::Detection,  "[DETECTION] "},
            { LogType::Info, "[INFO] " },
            { LogType::Err, "[ERROR] " },
            { LogType::Warning, "[WARNING] " }
        };

        msg_with_errorcode = msgsTypes.at(type);
        msg_with_errorcode += message;

        logToFile(msg_with_errorcode);

        SetColor(getLogColor(type));
        printf("%s\n", msg_with_errorcode.c_str());
        ResetColor();
    }

    static void logToWFile(std::wstring& message) 
    {
        if (logFileName.empty()) 
        {
            return;
        }
        
        std::wofstream logFile(logFileName, std::ios::out | std::ios::app);
        
        if (!logFile.is_open())
        {
            std::cerr << "Error: Could not open log file: " << logFileName << std::endl;
            return;
        }

        std::time_t now = std::time(nullptr);
        std::tm localtime;
        localtime_s(&localtime, &now);
        wchar_t timestamp[256] = { 0 };
        std::wcsftime(timestamp, 256, L"%Y-%m-%d %H:%M:%S", &localtime);

        logFile << L"[" << timestamp << L"] " << message << std::endl;

        if (logFile.fail())
        {
            std::cerr << "[ERROR] Failed to write to log file: " << logFileName << std::endl;
            return;
        }

        logFile.close(); // Close the file after writing
    }


    static void logw(LogType type, const std::wstring& message)
    {
        if (!enableLogging) 
        {
            return;
        }

        std::lock_guard<std::mutex> lock(consoleMutex);

        std::wstring msg_with_errorcode;

        const std::map<LogType, const std::wstring> msgsTypes =
        {
            { LogType::Detection,  L"[DETECTION] "},
            { LogType::Info, L"[INFO] " },
            { LogType::Err, L"[ERROR] " },
            { LogType::Warning, L"[WARNING] " }
        };

        msg_with_errorcode = msgsTypes.at(type);
        msg_with_errorcode += message;
        logToWFile(msg_with_errorcode);

        SetColor(getLogColor(type));
        wprintf(L"%s\n", msg_with_errorcode.c_str());
        ResetColor();
    }

    template<typename... Args>
    static void logf(LogType type, const char* format, Args... args)
    {
        if (format == NULL)
            return;

        const int buffSize = 1024;
        char buffer[buffSize] {0};

        int ret = std::snprintf(buffer, buffSize, format, args...);

        if (ret >= 0 && ret < buffSize)
        {
            log(type, std::string(buffer));
        }
        else 
        {
            std::cerr << "[WARNING] Failed to format log message." << std::endl;
        }
    }

    template<typename... Args>
    static void logfw(LogType type, const wchar_t* format, Args... args)
    {
        if (format == NULL)
            return;

        const int buffSize = 1024;
        wchar_t buffer[buffSize]{ 0 };

        int ret = _snwprintf(buffer, buffSize, format, args...);
        if (ret >= 0 && ret < buffSize)
        {
            logw(type, std::wstring(buffer));
        }
        else
        {
            std::cerr << "[WARNING] Failed to format log message." << std::endl;
        }
    }

    static void SetColor(int color) 
    {
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        SetConsoleTextAttribute(hConsole, color);
    }

    static void ResetColor()
    {
        SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    }

    template<typename... Args>
    static bool LogErrorAndReturn(const char* format, Args... args)
    {
		logf(Err, format, args...);
        return false;
    }

    static std::mutex consoleMutex;//prevent race conditions with text color changing
};