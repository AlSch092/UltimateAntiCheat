//AlSch092 @ Github
#include "Logger.hpp"

bool Logger::enableLogging = true;
std::string Logger::logFileName = "";
std::mutex Logger::consoleMutex;
