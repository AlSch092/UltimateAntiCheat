//By AlSch092 @github
#include "HttpClient.hpp"

/**
 * @brief Sends a GET HTTP request to a specified URL
 *
 * @param requestInfo Structure containing request data, along with response text
 *
 * @return true/false if request was successful
 *
 * @usage
 * bool wasSuccess = HttpClient::ReadWebPage(requestInfo);
 */
bool HttpClient::GetRequest(__inout HttpRequest& requestInfo) //GET request
{
    const int OPERATION_TIMEOUT = 15L;
    const int CONNECT_TIMEOUT = 15L;

    bool wasSuccess = false;

    CURL* curl = nullptr;
    CURLcode res;

    curl_global_init(CURL_GLOBAL_DEFAULT); // Initialize libcurl
    curl = curl_easy_init();

    struct curl_slist* request_headers = NULL;
    std::vector<std::string> response_headers;

    if (curl)
    {
        curl_easy_setopt(curl, CURLOPT_URL, requestInfo.url.c_str());

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &requestInfo.responseText);

        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, HeaderCallback);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, &response_headers);

        //set cookie
        curl_easy_setopt(curl, CURLOPT_COOKIE, requestInfo.cookie.c_str());

        curl_easy_setopt(curl, CURLOPT_TIMEOUT, OPERATION_TIMEOUT);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, CONNECT_TIMEOUT);

        if (requestInfo.requestHeaders.size() > 0)
        {
            for (const std::string& header : requestInfo.requestHeaders)
            {
                request_headers = curl_slist_append(request_headers, header.c_str());
            }

            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, request_headers);
        }

        res = curl_easy_perform(curl);

        if (res != CURLE_OK)
        {
#ifdef ENABLE_LOGGING
            Logger::logf(Warning, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
#endif
            goto cleanup;
        }

        for (const auto& response_header : response_headers) //extract cookies from header if needed or do any additional parsing
        {
            requestInfo.responseHeaders.push_back(response_header);
        }

        wasSuccess = true;
    }

cleanup:
    if (requestInfo.requestHeaders.size() > 0)
    {
        curl_slist_free_all(request_headers);
    }

    curl_easy_cleanup(curl);
    curl_global_cleanup();
    return wasSuccess;
}

/**
 * @brief Sends a POST HTTP request to a specified URL
 *
 * @param requestInfo Structure containing request data, along with response text
 *
 * @return true/false if request was successful
 *
 * @usage
 * bool wasSuccess = HttpClient::PostRequest(requestInfo);
 */
bool HttpClient::PostRequest(__inout HttpRequest& requestInfo)
{
    bool wasSuccess = false;
    CURL* curl = nullptr;
    CURLcode res;

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if (curl)
    {
        curl_easy_setopt(curl, CURLOPT_URL, requestInfo.url.c_str());

        curl_easy_setopt(curl, CURLOPT_POST, 1L);

        struct curl_slist* request_headers = NULL;

        if (requestInfo.requestHeaders.size() > 0)
        {
            for (const std::string& header : requestInfo.requestHeaders)
            {
                request_headers = curl_slist_append(request_headers, header.c_str());
            }

            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, request_headers); //set headers
        }

        curl_easy_setopt(curl, CURLOPT_COOKIE, requestInfo.cookie.c_str()); //set cookie

        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, requestInfo.body.c_str()); //set body

        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L); // Timeout for the whole operation in seconds
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L); // Timeout for the connection phase in seconds

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);         // Set the callback function to handle the response data

        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, HeaderCallback);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, &requestInfo.responseHeaders);

        curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);

        // Set the data pointer
        curl_easy_setopt(curl, CURLOPT_READDATA, (void*)0);

        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &requestInfo.responseText); //response data , write to

        res = curl_easy_perform(curl);

        if (res != CURLE_OK)
        {
#ifdef LOGGING_ENABLED
            Logger::logf(Warning, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
#endif
            goto fail_cleanup;
        }

        if (request_headers != nullptr)
            curl_slist_free_all(request_headers);

        curl_easy_cleanup(curl);
        curl_global_cleanup();
        return true;
    }
    else
    {
#ifdef LOGGING_ENABLED
        Logger::logf(Err, "Failed to initialize libcurl @ HttpClient::PostRequest");
#endif
        return false;
    }

fail_cleanup:
    curl_global_cleanup();
    return false;
}

size_t HttpClient::WriteCallback(void* contents, size_t size, size_t nmemb, std::string* s)
{
    size_t totalSize = size * nmemb;
    s->append((char*)contents, totalSize);
    return totalSize;
}

size_t HttpClient::WriteMemoryCallback(void* contents, size_t size, size_t nmemb, void* userp)
{
    size_t totalSize = size * nmemb;
    MemoryStruct* mem = (MemoryStruct*)userp;
    mem->memory.insert(mem->memory.end(), (unsigned char*)contents, (unsigned char*)contents + totalSize);
    return totalSize;
}

size_t HttpClient::HeaderCallback(char* buffer, size_t size, size_t nitems, void* userdata)
{
    size_t totalSize = size * nitems;
    std::string header(buffer, totalSize);
    ResponseHeaders* responseHeaders = static_cast<ResponseHeaders*>(userdata);
    responseHeaders->headers.push_back(header);
    return totalSize;
}

// Callback function to read data.. un-hangs logout request for some reason if we specify a read callback on curl request
size_t HttpClient::read_callback(void* ptr, size_t size, size_t nmemb, void* userdata)
{
    return 0;
}