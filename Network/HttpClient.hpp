//By AlSch092 @github
#pragma once
#include <iostream>
#include <string>
#include <vector>
#include "curl/curl.h"
#include "curl/easy.h"
#include "../Common/Logger.hpp"

#ifdef _DEBUG
#pragma comment(lib, "Libs/libcurl-d.lib")
#else
#pragma comment(lib, "Libs/libcurl.lib") //located in project root folder
#endif

using namespace std;

struct MemoryStruct
{
    std::vector<unsigned char> memory;
};

struct ResponseHeaders
{
    vector<std::string> headers;
};

class HttpClient //a simple class for making web/http requests.
{
public:

    static string ReadWebPage(__in const string url, __in const vector<string> headers, __in const string cookie, __out vector<string>& responseHeaders);
    static string PostRequest(__in const string url, __in const vector<string> headers, __in const string cookie, __in const string body, __out vector<string>& responseHeaders);

private:
    static size_t read_callback(void* ptr, size_t size, size_t nmemb, void* userdata);
    static size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* s);
    static size_t WriteMemoryCallback(void* contents, size_t size, size_t nmemb, void* userp);
    static size_t HeaderCallback(char* buffer, size_t size, size_t nitems, void* userdata);
};