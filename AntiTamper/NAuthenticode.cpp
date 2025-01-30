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
			Logger::log("UltimateAnticheat.log", LogType::Detection, "Revoked signature detected");
			return FALSE;
		}
    }

    /* success, cleanup */
    winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &actionGUID, &winTrustData);

    return TRUE;
}

BOOL Authenticode::VerifyCatalogSignature(LPCWSTR filePath) 
{
    HANDLE hFile = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) 
    {
        Logger::logfw("UltimateAnticheat.log", LogType::Warning, L"Could not open file: %s @ VerifyCatalogSignature", filePath);
        return false;
    }

    HCATADMIN hCatAdmin = NULL;
    if (!CryptCATAdminAcquireContext(&hCatAdmin, NULL, 0)) 
    {
        CloseHandle(hFile);
        return false;
    }

    BYTE pbHash[100];
    DWORD cbHash = sizeof(pbHash);
    if (!CryptCATAdminCalcHashFromFileHandle(hFile, &cbHash, pbHash, 0)) 
    {
        CryptCATAdminReleaseContext(hCatAdmin, 0);
        CloseHandle(hFile);
        return false;
    }

    CATALOG_INFO CatInfo;
    memset(&CatInfo, 0, sizeof(CATALOG_INFO));
    CatInfo.cbStruct = sizeof(CATALOG_INFO);

    HCATINFO hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, pbHash, cbHash, 0, NULL);
    if (hCatInfo == NULL) 
    {
        Logger::logfw("UltimateAnticheat.log", LogType::Warning, L"No catalog file found for: %s @ VerifyCatalogSignature", filePath);
        CryptCATAdminReleaseContext(hCatAdmin, 0);
        CloseHandle(hFile);
        return false;
    }

    if (!CryptCATCatalogInfoFromContext(hCatInfo, &CatInfo, 0)) 
    {
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
    return (Authenticode::VerifyCatalogSignature(filePath) || Authenticode::VerifyEmbeddedSignature(filePath));
}

BOOL Authenticode::GetDateOfTimeStamp(PCMSG_SIGNER_INFO pSignerInfo, SYSTEMTIME* st)
{
    BOOL fResult;
    FILETIME lft, ft;
    DWORD dwData;
    BOOL fReturn = FALSE;

    // Loop through authenticated attributes and find
    // szOID_RSA_signingTime OID.
    for (DWORD n = 0; n < pSignerInfo->AuthAttrs.cAttr; n++)
    {
        if (lstrcmpA(szOID_RSA_signingTime,  pSignerInfo->AuthAttrs.rgAttr[n].pszObjId) == 0)
        {
            // Decode and get FILETIME structure.
            dwData = sizeof(ft);
            fResult = CryptDecodeObject(ENCODING,
                szOID_RSA_signingTime,
                pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].pbData,
                pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].cbData,
                0,
                (PVOID)&ft,
                &dwData);
            if (!fResult)
            {
                Logger::logf("UltimateAnticheat.log", Err, "CryptDecodeObject failed with %x @ Authenticode::GetTimeStampSignerInfo", GetLastError());
                break;
            }

            // Convert to local time.
            FileTimeToLocalFileTime(&ft, &lft);
            FileTimeToSystemTime(&lft, st);

            fReturn = TRUE;

            break; // Break from for loop.

        } //lstrcmp szOID_RSA_signingTime
    } // for 

    return fReturn;
}

LPWSTR Authenticode::AllocateAndCopyWideString(LPCWSTR inputString) //used in other routines found in NAuthenticode.cpp
{
    LPWSTR outputString = NULL;

    outputString = (LPWSTR)LocalAlloc(LPTR, (wcslen(inputString) + 1) * sizeof(WCHAR));
    
    if (outputString != NULL)
        lstrcpyW(outputString, inputString);
    
    return outputString;
}

BOOL Authenticode::GetProgAndPublisherInfo(PCMSG_SIGNER_INFO pSignerInfo, PSPROG_PUBLISHERINFO Info)
{
    BOOL fReturn = FALSE;
    PSPC_SP_OPUS_INFO OpusInfo = NULL;
    DWORD dwData;
    BOOL fResult;

    __try
    {
        // Loop through authenticated attributes and find
        // SPC_SP_OPUS_INFO_OBJID OID.
        for (DWORD n = 0; n < pSignerInfo->AuthAttrs.cAttr; n++)
        {
            if (lstrcmpA(SPC_SP_OPUS_INFO_OBJID,
                pSignerInfo->AuthAttrs.rgAttr[n].pszObjId) == 0)
            {
                // Get Size of SPC_SP_OPUS_INFO structure.
                fResult = CryptDecodeObject(ENCODING,
                    SPC_SP_OPUS_INFO_OBJID,
                    pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].pbData,
                    pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].cbData,
                    0,
                    NULL,
                    &dwData);
                if (!fResult)
                {
                    Logger::logf("UltimateAnticheat.log", Err, "CryptDecodeObject failed with %x @ Authenticode::GetProgAndPublisherInfo", GetLastError());
                    __leave;
                }

                // Allocate memory for SPC_SP_OPUS_INFO structure.
                OpusInfo = (PSPC_SP_OPUS_INFO)LocalAlloc(LPTR, dwData);
                if (!OpusInfo)
                {
                    Logger::logf("UltimateAnticheat.log", Err, "Unable to allocate memory for publisher info @ Authenticode::GetProgAndPublisherInfo");
                    __leave;
                }

                // Decode and get SPC_SP_OPUS_INFO structure.
                fResult = CryptDecodeObject(ENCODING,
                    SPC_SP_OPUS_INFO_OBJID,
                    pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].pbData,
                    pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].cbData,
                    0,
                    OpusInfo,
                    &dwData);
                if (!fResult)
                {
                    Logger::logf("UltimateAnticheat.log", Err, "CryptDecodeObject failed with %x @ Authenticode::GetProgAndPublisherInfo", GetLastError());
                    __leave;
                }

                // Fill in Program Name if present.
                if (OpusInfo->pwszProgramName)
                {
                    Info->lpszProgramName =
                        AllocateAndCopyWideString(OpusInfo->pwszProgramName);
                }
                else
                    Info->lpszProgramName = NULL;

                // Fill in Publisher Information if present.
                if (OpusInfo->pPublisherInfo)
                {

                    switch (OpusInfo->pPublisherInfo->dwLinkChoice)
                    {
                    case SPC_URL_LINK_CHOICE:
                        Info->lpszPublisherLink =
                            AllocateAndCopyWideString(OpusInfo->pPublisherInfo->pwszUrl);
                        break;

                    case SPC_FILE_LINK_CHOICE:
                        Info->lpszPublisherLink =
                            AllocateAndCopyWideString(OpusInfo->pPublisherInfo->pwszFile);
                        break;

                    default:
                        Info->lpszPublisherLink = NULL;
                        break;
                    }
                }
                else
                {
                    Info->lpszPublisherLink = NULL;
                }

                // Fill in More Info if present.
                if (OpusInfo->pMoreInfo)
                {
                    switch (OpusInfo->pMoreInfo->dwLinkChoice)
                    {
                    case SPC_URL_LINK_CHOICE:
                        Info->lpszMoreInfoLink =
                            AllocateAndCopyWideString(OpusInfo->pMoreInfo->pwszUrl);
                        break;

                    case SPC_FILE_LINK_CHOICE:
                        Info->lpszMoreInfoLink =
                            AllocateAndCopyWideString(OpusInfo->pMoreInfo->pwszFile);
                        break;

                    default:
                        Info->lpszMoreInfoLink = NULL;
                        break;
                    }
                }
                else
                {
                    Info->lpszMoreInfoLink = NULL;
                }

                fReturn = TRUE;

                break; // Break from for loop.
            } // lstrcmp SPC_SP_OPUS_INFO_OBJID 
        } // for 
    }
    __finally
    {
        if (OpusInfo != NULL) LocalFree(OpusInfo);
    }

    return fReturn;
}

BOOL Authenticode::GetTimeStampSignerInfo(PCMSG_SIGNER_INFO pSignerInfo, PCMSG_SIGNER_INFO* pCounterSignerInfo)
{
    PCCERT_CONTEXT pCertContext = NULL;
    BOOL fReturn = FALSE;
    BOOL fResult;
    DWORD dwSize;

    __try
    {
        *pCounterSignerInfo = NULL;

        // Loop through unathenticated attributes for
        // szOID_RSA_counterSign OID.
        for (DWORD n = 0; n < pSignerInfo->UnauthAttrs.cAttr; n++)
        {
            if (lstrcmpA(pSignerInfo->UnauthAttrs.rgAttr[n].pszObjId,
                szOID_RSA_counterSign) == 0)
            {
                // Get size of CMSG_SIGNER_INFO structure.
                fResult = CryptDecodeObject(ENCODING,
                    PKCS7_SIGNER_INFO,
                    pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].pbData,
                    pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].cbData,
                    0,
                    NULL,
                    &dwSize);
                if (!fResult)
                {
                    Logger::logf("UltimateAnticheat.log", Err, "CryptDecodeObject failed with %x @ Authenticode::GetTimeStampSignerInfo", GetLastError());
                    __leave;
                }

                // Allocate memory for CMSG_SIGNER_INFO.
                *pCounterSignerInfo = (PCMSG_SIGNER_INFO)LocalAlloc(LPTR, dwSize);
                if (!*pCounterSignerInfo)
                {
                    Logger::logf("UltimateAnticheat.log", Err, "Unable to allocate memory for timestamp info @ Authenticode::GetTimeStampSignerInfo");
                    __leave;
                }

                // Decode and get CMSG_SIGNER_INFO structure
                // for timestamp certificate.
                fResult = CryptDecodeObject(ENCODING,
                    PKCS7_SIGNER_INFO,
                    pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].pbData,
                    pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].cbData,
                    0,
                    (PVOID)*pCounterSignerInfo,
                    &dwSize);
                if (!fResult)
                {
                    Logger::logf("UltimateAnticheat.log", Err, "CryptDecodeObject failed with %x @ Authenticode::GetTimeStampSignerInfo", GetLastError());
                    __leave;
                }

                fReturn = TRUE;

                break; // Break from for loop.
            }
        }
    }
    __finally
    {
        // Clean up.
        if (pCertContext != NULL) CertFreeCertificateContext(pCertContext);
    }

    return fReturn;
}


wstring Authenticode::GetCertificateSubject(PCCERT_CONTEXT pCertContext)
{
    BOOL fReturn = FALSE;
    LPTSTR szName = NULL;
    DWORD dwData;

    // Print Serial Number.
    //_tprintf(_T("Serial Number: "));
    dwData = pCertContext->pCertInfo->SerialNumber.cbData;

    //for (DWORD n = 0; n < dwData; n++)
    //{
    //    _tprintf(_T("%02x "), pCertContext->pCertInfo->SerialNumber.pbData[dwData - (n + 1)]);
    //}
    //_tprintf(_T("\n"));

    // Get Issuer name size.
    if (!(dwData = CertGetNameString(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL, NULL, 0)))
    {
        Logger::logf("UltimateAnticheat.log", Err, "CertGetNameString failed @ GetCertificateSubject");
        goto end;
    }

    // Allocate memory for Issuer name.
    szName = (LPTSTR)LocalAlloc(LPTR, dwData * sizeof(TCHAR));
    if (!szName)
    {
        Logger::logf("UltimateAnticheat.log", Err, "Unable to allocate memory for issuer name @ GetCertificateSubject");
        goto end;
    }

    // Get Issuer name.
    if (!(CertGetNameString(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL, szName, dwData)))
    {
        Logger::logf("UltimateAnticheat.log", Err, "CertGetNameString failed @ GetCertificateSubject");
        goto end;
    }

    // print Issuer name.
    //_tprintf(_T("Issuer Name: %s\n"), szName);
    LocalFree(szName);
    szName = NULL;

    // Get Subject name size.
    if (!(dwData = CertGetNameString(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, NULL, 0)))
    {
        Logger::logf("UltimateAnticheat.log", Err, "CertGetNameString failed @ GetCertificateSubject");
        goto end;
    }

    // Allocate memory for subject name.
    szName = (LPTSTR)LocalAlloc(LPTR, dwData * sizeof(TCHAR));
    if (!szName)
    {
        Logger::logf("UltimateAnticheat.log", Err, "Unable to allocate memory for subject name @ GetCertificateSubject");
        goto end;
    }

    // Get subject name.
    if (!(CertGetNameString(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, szName, dwData)))
    {
        Logger::logf("UltimateAnticheat.log", Err, "CertGetNameString failed @ GetCertificateSubject");
        goto end;
    }

    // Print Subject Name.
    //_tprintf(_T("Subject Name: %s\n"), szName);
    return wstring(szName);
    fReturn = TRUE;

end:
    if (szName != NULL) LocalFree(szName);

    return {};
}


wstring Authenticode::GetSignerFromFile(const std::wstring& filePath)
{
    WCHAR szFileName[MAX_PATH];
    HCERTSTORE hStore = NULL;
    HCRYPTMSG hMsg = NULL;
    PCCERT_CONTEXT pCertContext = NULL;
    BOOL fResult;
    DWORD dwEncoding, dwContentType, dwFormatType;
    PCMSG_SIGNER_INFO pSignerInfo = NULL;
    PCMSG_SIGNER_INFO pCounterSignerInfo = NULL;
    DWORD dwSignerInfo;
    CERT_INFO CertInfo;
    SPROG_PUBLISHERINFO ProgPubInfo;

    ZeroMemory(&ProgPubInfo, sizeof(ProgPubInfo));
    lstrcpynW(szFileName, filePath.c_str(), MAX_PATH);

    // Get message handle and store handle from the signed file.
    fResult = CryptQueryObject(CERT_QUERY_OBJECT_FILE,
        szFileName,
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY,
        0,
        &dwEncoding,
        &dwContentType,
        &dwFormatType,
        &hStore,
        &hMsg,
        NULL);
    if (!fResult)
    {
        Logger::logf("UltimateAnticheat.log", Err, "CryptQueryObject failed with %x @ GetSignerFromFile", GetLastError());
        return {};
    }

    // Get signer information size.
    fResult = CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &dwSignerInfo);

    if (!fResult)
    {
        Logger::logf("UltimateAnticheat.log", Err, "CryptMsgGetParam failed with %x @ GetSignerFromFile", GetLastError());
        return {};
    }

    // Allocate memory for signer information.
    pSignerInfo = (PCMSG_SIGNER_INFO)LocalAlloc(LPTR, dwSignerInfo);

    if (!pSignerInfo)
    {
        Logger::logf("UltimateAnticheat.log", Err, "Unable to allocate memory for Signer Info @ GetSignerFromFile");
        return {};
    }

    // Get Signer Information.
    fResult = CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, (PVOID)pSignerInfo, &dwSignerInfo);

    if (!fResult)
    {
        Logger::logf("UltimateAnticheat.log", Err, "CryptMsgGetParam failed with %x @ GetSignerFromFile", GetLastError());
        return {};
    }

    // Get program name and publisher information from 
    // signer info structure.
    if (GetProgAndPublisherInfo(pSignerInfo, &ProgPubInfo))
    {
        //if (ProgPubInfo.lpszProgramName != NULL)
        //{
        //    wprintf(L"Program Name : %s\n",
        //        ProgPubInfo.lpszProgramName);
        //}

        //if (ProgPubInfo.lpszPublisherLink != NULL)
        //{
        //    wprintf(L"Publisher Link : %s\n",
        //        ProgPubInfo.lpszPublisherLink);
        //}

        //if (ProgPubInfo.lpszMoreInfoLink != NULL)
        //{
        //    wprintf(L"MoreInfo Link : %s\n",
        //        ProgPubInfo.lpszMoreInfoLink);
        //}
    }

    // Search for the signer certificate in the temporary 
    // certificate store.
    CertInfo.Issuer = pSignerInfo->Issuer;
    CertInfo.SerialNumber = pSignerInfo->SerialNumber;

    pCertContext = CertFindCertificateInStore(hStore,
        ENCODING,
        0,
        CERT_FIND_SUBJECT_CERT,
        (PVOID)&CertInfo,
        NULL);
    if (!pCertContext)
    {
        Logger::logf("UltimateAnticheat.log", Err, "CertFindCertificateInStore failed with %x @ GetSignerFromFile", GetLastError());
        return {};
    }

    wstring SubjectCert = GetCertificateSubject(pCertContext);

    //// Get the timestamp certificate signerinfo structure.
    //if (GetTimeStampSignerInfo(pSignerInfo, &pCounterSignerInfo))
    //{
    //    // Search for Timestamp certificate in the temporary
    //    // certificate store.
    //    CertInfo.Issuer = pCounterSignerInfo->Issuer;
    //    CertInfo.SerialNumber = pCounterSignerInfo->SerialNumber;

    //    pCertContext = CertFindCertificateInStore(hStore,
    //        ENCODING,
    //        0,
    //        CERT_FIND_SUBJECT_CERT,
    //        (PVOID)&CertInfo,
    //        NULL);
    //    if (!pCertContext)
    //    {
    //        _tprintf(_T("CertFindCertificateInStore failed with %x\n"),
    //            GetLastError());
    //        return {};
    //    }

    //    // Print timestamp certificate information.
    //    _tprintf(_T("TimeStamp Certificate:\n\n"));
    //    PrintCertificateInfo(pCertContext);
    //    _tprintf(_T("\n"));

    //    // Find Date of timestamp.
    //    if (GetDateOfTimeStamp(pCounterSignerInfo, &st))
    //    {
    //        _tprintf(_T("Date of TimeStamp : %02d/%02d/%04d %02d:%02d\n"),
    //            st.wMonth,
    //            st.wDay,
    //            st.wYear,
    //            st.wHour,
    //            st.wMinute);
    //    }
    //    _tprintf(_T("\n"));
    //}
    //Logger::log("UltimateAnticheat.log", LogType::Warning, "Failed to query file's digital signature @ GetSignerFromFile");

    return SubjectCert;
}
