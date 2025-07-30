//By AlSch092 @github
#pragma once
#include <iostream>
#include <string>
#include <vector>
#include "curl/curl.h"
#include "curl/easy.h"
#include "../Common/Logger.hpp"

using namespace std;

struct HttpRequest
{
    string url;
    vector<string> requestHeaders;
    string cookie;
    string body;
    vector<string> responseHeaders;
    string responseText;
};

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

    static bool GetRequest(__inout HttpRequest& requestInfo);
    static bool PostRequest(__inout HttpRequest& requestInfo);

private:
    static size_t read_callback(void* ptr, size_t size, size_t nmemb, void* userdata);
    static size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* s);
    static size_t WriteMemoryCallback(void* contents, size_t size, size_t nmemb, void* userp);
    static size_t HeaderCallback(char* buffer, size_t size, size_t nitems, void* userdata);
};