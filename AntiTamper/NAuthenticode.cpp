#include "NAuthenticode.hpp"

BOOL Authenticode::VerifyEmbeddedSignature(LPCWSTR filePath)
{
    WINTRUST_FILE_INFO fileData;
    WINTRUST_DATA winTrustData;
    GUID actionGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    memset(&fileData, 0, sizeof(fileData));
    fileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileData.pcwszFilePath = filePath;

    memset(&winTrustData, 0, sizeof(winTrustData));
    winTrustData.cbStruct = sizeof(WINTRUST_DATA);
    winTrustData.dwUIChoice = WTD_UI_NONE;
    winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    winTrustData.pFile = &fileData;
    winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;

    LONG status = WinVerifyTrust(NULL, &actionGUID, &winTrustData);

    if (status != ERROR_SUCCESS)
    {
        if (status == TRUST_E_NOSIGNATURE || status == TRUST_E_BAD_DIGEST)
            return FALSE;

        if (status == CERT_E_REVOKED || status == CERT_E_EXPIRED || status == CERT_E_UNTRUSTEDROOT || status == CERT_E_CHAINING)
        {
			Logger::log("AntiTamper.log", LogType::Detection, "Revoked signature detected"); // todo: flag 
			return FALSE;
		}
    }

    /* success, cleanup */
    winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &actionGUID, &winTrustData);

    return TRUE;
}

BOOL Authenticode::VerifyCatalogSignature(LPCWSTR filePath) {
    HANDLE hFile = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::wcerr << L"Could not open file: " << filePath << std::endl;
        return false;
    }

    HCATADMIN hCatAdmin = NULL;
    if (!CryptCATAdminAcquireContext(&hCatAdmin, NULL, 0)) {
        CloseHandle(hFile);
        return false;
    }

    BYTE pbHash[100];
    DWORD cbHash = sizeof(pbHash);
    if (!CryptCATAdminCalcHashFromFileHandle(hFile, &cbHash, pbHash, 0)) {
        CryptCATAdminReleaseContext(hCatAdmin, 0);
        CloseHandle(hFile);
        return false;
    }

    CATALOG_INFO CatInfo;
    memset(&CatInfo, 0, sizeof(CATALOG_INFO));
    CatInfo.cbStruct = sizeof(CATALOG_INFO);

    HCATINFO hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, pbHash, cbHash, 0, NULL);
    if (hCatInfo == NULL) {
        //std::wcerr << L"No catalog file found for " << filePath << std::endl;
        CryptCATAdminReleaseContext(hCatAdmin, 0);
        CloseHandle(hFile);
        return false;
    }

    if (!CryptCATCatalogInfoFromContext(hCatInfo, &CatInfo, 0)) {
        CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
        CryptCATAdminReleaseContext(hCatAdmin, 0);
        CloseHandle(hFile);
        return false;
    }

    WINTRUST_CATALOG_INFO WinTrustCatalogInfo;
    memset(&WinTrustCatalogInfo, 0, sizeof(WinTrustCatalogInfo));
    WinTrustCatalogInfo.cbStruct = sizeof(WINTRUST_CATALOG_INFO);
    WinTrustCatalogInfo.pcwszCatalogFilePath = CatInfo.wszCatalogFile;
    WinTrustCatalogInfo.pcwszMemberTag = NULL;
    WinTrustCatalogInfo.pcwszMemberFilePath = filePath;
    WinTrustCatalogInfo.hMemberFile = hFile;
    WinTrustCatalogInfo.pbCalculatedFileHash = pbHash;
    WinTrustCatalogInfo.cbCalculatedFileHash = cbHash;

    GUID ActionGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA WinTrustData;
    memset(&WinTrustData, 0, sizeof(WinTrustData));
    WinTrustData.cbStruct = sizeof(WINTRUST_DATA);
    WinTrustData.pPolicyCallbackData = NULL;
    WinTrustData.pSIPClientData = NULL;
    WinTrustData.dwUIChoice = WTD_UI_NONE;
    WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    WinTrustData.dwUnionChoice = WTD_CHOICE_CATALOG;
    WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    WinTrustData.hWVTStateData = NULL;
    WinTrustData.pwszURLReference = NULL;
    WinTrustData.dwProvFlags = WTD_REVOCATION_CHECK_NONE;
    WinTrustData.dwUIContext = 0;
    WinTrustData.pCatalog = &WinTrustCatalogInfo;

    LONG lStatus = WinVerifyTrust(NULL, &ActionGuid, &WinTrustData);

    WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &ActionGuid, &WinTrustData);

    CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
    CryptCATAdminReleaseContext(hCatAdmin, 0);
    CloseHandle(hFile);

    return lStatus == ERROR_SUCCESS;
}

/// <summary>
/// Takes in a file path and returns if module is signed of not
/// </summary>
/// <param name="filePath:">Full file path to DLL</param>
/// <returns>True if file has a signature</returns>
BOOL Authenticode::HasSignature(LPCWSTR filePath)
{
    return (Authenticode::VerifyEmbeddedSignature(filePath) ||
        Authenticode::VerifyCatalogSignature(filePath));
}