//By AlSch092 @github
#pragma once
#include <iostream>
#include <string>
#include "curl/curl.h"
#include "curl/easy.h"
#include <vector>

#ifdef _DEBUG
#pragma comment(lib, "libcurl-d.lib")
#else
#pragma comment(lib, "libcurl.lib") //located in project root folder
#endif

using namespace std;

struct ResponseHeaders
{
    vector<std::string> headers;
};

class HttpClient //a simple class for making web/http requests. *** CLASS CURRENTLY IN-PROGRESS / NOT FINISHED  ***
{
public:

    string ReadWebPage(__in string url, __in vector<string> headers, __in string cookie);

private:
    CURL* curl = nullptr;
    CURLcode res;

    static size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* s);
    static size_t HeaderCallback(char* buffer, size_t size, size_t nitems, void* userdata);
};