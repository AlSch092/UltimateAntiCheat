//By AlSch092 @github
#include "EventReporter.hpp"
#include "../Common/Logger.hpp"

EventReporter::EventReporter(const std::string& apiDomain)
    : apiDomain(apiDomain)
{
    if (this->apiDomain.empty())
    {
        Logger::logf(Warning, "EventReporter initialized with empty API domain");
    }
    else
    {
        // Remove trailing slash if present
        if (this->apiDomain.back() == '/')
        {
            this->apiDomain.pop_back();
        }
        Logger::logf(Info, "EventReporter initialized with domain: %s", this->apiDomain.c_str());
    }
}

bool EventReporter::ReportDetection(
    __in DetectionFlags flag,
    __in const std::string& detectionName,
    __in const std::string& detectionDetails,
    __in DWORD processId)
{
    if (this->apiDomain.empty())
    {
        this->lastError = "API domain not configured";
        Logger::logf(Warning, "Cannot report detection: API domain not configured");
        return false;
    }

    // Collect MAC addresses
    std::vector<std::string> macAddresses = Utility::GetMACAddresses();
    if (macAddresses.empty())
    {
        Logger::logf(Warning, "No MAC addresses found for detection report");
    }

    // Build JSON payload
    std::string jsonPayload = BuildDetectionPayload(flag, detectionName, detectionDetails, processId, macAddresses);

    // Build the full URL
    std::string url = this->apiDomain + "/events/log";

    // Prepare HTTP request
    HttpRequest request;
    request.url = url;
    request.body = jsonPayload;
    request.requestHeaders.push_back("Content-Type: application/json");
    request.requestHeaders.push_back("User-Agent: UltimateAntiCheat/2.1");

    // Send POST request
    Logger::logf(Info, "Sending detection event to API: %s", url.c_str());

    bool success = HttpClient::PostRequest(request);

    if (success)
    {
        Logger::logf(Info, "Detection event sent successfully. Response: %s", request.responseText.c_str());
        this->lastError = "";
        return true;
    }
    else
    {
        this->lastError = "Failed to send HTTP request";
        Logger::logf(Err, "Failed to send detection event to API");
        return false;
    }
}

std::string EventReporter::BuildDetectionPayload(
    __in DetectionFlags flag,
    __in const std::string& detectionName,
    __in const std::string& detectionDetails,
    __in DWORD processId,
    __in const std::vector<std::string>& macAddresses)
{
    json payload;

    // Add detection information
    payload["detection_type"] = static_cast<int>(flag);
    payload["detection_name"] = detectionName;
    payload["detection_details"] = detectionDetails;
    payload["process_id"] = processId;
    payload["timestamp"] = static_cast<long long>(time(nullptr));

    // Add MAC addresses
    json macArray = json::array();
    for (const auto& mac : macAddresses)
    {
        macArray.push_back(mac);
    }
    payload["mac_addresses"] = macArray;

    // Add system information
    payload["platform"] = "Windows";

    #ifdef _WIN64
    payload["architecture"] = "x64";
    #else
    payload["architecture"] = "x86";
    #endif

    return payload.dump();
}
