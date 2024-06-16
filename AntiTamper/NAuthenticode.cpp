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

    winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &actionGUID, &winTrustData);

    if (status == ERROR_SUCCESS) 
    {
        return TRUE;
    }
    else 
    {
        if (status == TRUST_E_NOSIGNATURE || status == TRUST_E_BAD_DIGEST)  //check for associated catalog file -> todo
        {
        }

        return FALSE;
    }

    return (status == ERROR_SUCCESS);
}