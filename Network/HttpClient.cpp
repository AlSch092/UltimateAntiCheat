//By AlSch092 @github
#include "HttpClient.hpp"

/*
    ReadWebPage - returns contents at `url` using cURL library
    returns empty string on failure
*/
string HttpClient::ReadWebPage(__in string url, __in vector<string> headers, __in string cookie) //GET request
{   
    const int OPERATION_TIMEOUT = 15L;
    const int CONNECT_TIMEOUT = 15L;

    curl_global_init(CURL_GLOBAL_DEFAULT); // Initialize libcurl
    curl = curl_easy_init();

    struct curl_slist* request_headers = NULL;
    vector<std::string> response_headers;

    string readBuffer;

    if (curl)
    {
        curl_easy_setopt(curl, CURLOPT_URL, url);

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);

        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, HeaderCallback);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, &response_headers);

        //set cookie
        curl_easy_setopt(curl, CURLOPT_COOKIE, cookie.c_str()); //cookie should be "all cookies combined" , for example "a=12345;b=222;csef_token=blahblah"

        curl_easy_setopt(curl, CURLOPT_TIMEOUT, OPERATION_TIMEOUT); 
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, CONNECT_TIMEOUT);

        if (headers.size() > 0)
        {
            for (string header : headers)
            {
                request_headers = curl_slist_append(request_headers, header.c_str());
            }

            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        }

        res = curl_easy_perform(curl);

        if (res != CURLE_OK)
        {
            std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
            goto cleanup;
        }    

        for (const auto& response_header : response_headers) //extract cookies from header if needed or do any additional parsing
        {
            cout << "Response header: " << response_header << endl;
        }
    }

cleanup:
    if (headers.size() > 0)
    {
        curl_slist_free_all(request_headers);
    }

    curl_easy_cleanup(curl);
    curl_global_cleanup();
    return readBuffer;
}

size_t HttpClient::WriteCallback(void* contents, size_t size, size_t nmemb, std::string* s)
{
    size_t totalSize = size * nmemb;
    s->append((char*)contents, totalSize);
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