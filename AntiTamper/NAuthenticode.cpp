#include "NAuthenticode.hpp"

/**
 * @brief Checks code signature of a file through either embedded signature or catalog signature
 *
 * @param filePath The file path to the executable or DLL to check
 * @param checkEndCertRevoked Whether or not to check if the end certificate is revoked
 *
 * @return true/false if `filePath` has a valid signature
 *
 * @usage
 * BOOL isSigned = Authenticode::HasSignature(L"myfile.exe", TRUE);
 */
BOOL Authenticode::HasSignature(__in const LPCWSTR filePath, __in const  BOOL checkEndCertRevoked)
{
    return (Authenticode::VerifyEmbeddedSignature(filePath, checkEndCertRevoked) || Authenticode::VerifyCatalogSignature(filePath, checkEndCertRevoked));
}

/**
 * @brief Checks code signature of a file through its embedded signature
 *
 *
 * @param filePath The file path to the executable or DLL to check
 * @param checkEndCertRevoked Whether or not to check if the end certificate is revoked
 *
 * @return true/false if `filePath` has a valid embedded signature
 *
 * @usage
 * BOOL hasEmbeddedSig = Authenticode::VerifyEmbeddedSignature(L"myfile.exe", TRUE);
 */
BOOL Authenticode::VerifyEmbeddedSignature(__in const LPCWSTR filePath, __in const  BOOL checkRevoked)
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

    if (!checkRevoked)
        winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE; //speed up execution, but decrease security
    else
        winTrustData.fdwRevocationChecks = WTD_REVOCATION_CHECK_END_CERT; //checking the whole chain for all modules is likely too much, tradeoff between speed and security

    winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    winTrustData.pFile = &fileData;
    winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    //winTrustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL; //only use cached CRL -> if no network access on the machine, this is helpful

    LONG status = 0;

    status = WinVerifyTrust(NULL, &actionGUID, &winTrustData);

    if (status != ERROR_SUCCESS)
    {
        if (status == TRUST_E_NOSIGNATURE || status == TRUST_E_BAD_DIGEST)
            return FALSE;

        if (status == CERT_E_REVOKED || status == CERT_E_EXPIRED || status == CERT_E_UNTRUSTEDROOT || status == CERT_E_CHAINING)
        {
			Logger::log(LogType::Detection, "Revoked or expired signature detected");
			return FALSE;
	}
    }

    /* success, cleanup */
    winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &actionGUID, &winTrustData);

    return TRUE;
}

/**
 * @brief Checks code signature of a file through its catalog file
 *
 * @param filePath The file path to the executable or DLL to check
 * @param checkEndCertRevoked Whether or not to check if the end certificate is revoked
 *
 * @return true/false if `filePath` has a valid catalog signature
 *
 * @usage
 * BOOL hasEmbeddedSig = Authenticode::VerifyCatalogSignature(L"myfile.exe", TRUE);
 */
BOOL Authenticode::VerifyCatalogSignature(__in const LPCWSTR filePath, __in const BOOL checkRevoked)
{
    HANDLE hFile = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) 
    {
        Logger::logfw(LogType::Warning, L"Could not open file: %s @ VerifyCatalogSignature", filePath);
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
        //Logger::logfw(LogType::Warning, L"No catalog file found for: %s @ VerifyCatalogSignature", filePath);
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

    if (!checkRevoked)
        WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE; //speed up execution, but decrease security
    else
        WinTrustData.fdwRevocationChecks = WTD_REVOCATION_CHECK_END_CERT; //checking the whole chain for all modules is likely too much, tradeoff between speed and security

    WinTrustData.dwUnionChoice = WTD_CHOICE_CATALOG;
    WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    WinTrustData.hWVTStateData = NULL;
    WinTrustData.pwszURLReference = NULL;
    //WinTrustData.dwProvFlags = WTD_REVOCATION_CHECK_NONE;
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

/**
 * @brief Checks the date of the time stamp of a signer info structure
 *
 * @param pSignerInfo Structure representing information about the cert signer
 * @param st          Structure representing a date timestamp, which is written to by the function
 *
 * @return true/false if successfully writes to `st` vargument
 *
 * @usage
 * SYSTEMTIME st = { 0 };
 * BOOL success = Authenticode::GetDateOfTimeStamp(pSignerInfo, &st);
 */
BOOL Authenticode::GetDateOfTimeStamp(__in const PCMSG_SIGNER_INFO pSignerInfo, __out SYSTEMTIME* st)
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
                Logger::logf(Err, "CryptDecodeObject failed with %x @ Authenticode::GetTimeStampSignerInfo", GetLastError());
                break;
            }

            // Convert to local time.
            FileTimeToLocalFileTime(&ft, &lft);
            FileTimeToSystemTime(&lft, st);

            fReturn = TRUE;

            break;
        }
    } 

    return fReturn;
}

/**
 * @brief Copies a wide string to a newly allocated memory block
 *
 * @param inputString String to be copied
 *
 * @return LPWSTR, or NULL if allocation failed
 *
 * @usage
 * LPWSTR pCopyStr = Authenticode::AllocateAndCopyWideString(L"Hello, World!");
 */
LPWSTR Authenticode::AllocateAndCopyWideString(__in const LPCWSTR inputString) //used in other routines found in NAuthenticode.cpp
{
    LPWSTR outputString = NULL;

    outputString = (LPWSTR)LocalAlloc(LPTR, (wcslen(inputString) + 1) * sizeof(WCHAR));
    
    if (outputString != NULL)
        lstrcpyW(outputString, inputString);
    
    return outputString;
}

/**
 * @brief Grabs the program and publisher information from a signer info structure
 *
 * @param pSignerInfo Structure representing the certificate signer info
 * @param Info Structure to fill, representing program and publisher information
 *
 * @return true/false if the information was successfully retrieved
 *
 * @usage
 * BOOL success = Authenticode::GetProgAndPublisherInfo(pSignerInfo, &publisherInfo);
 */
BOOL Authenticode::GetProgAndPublisherInfo(__in const PCMSG_SIGNER_INFO pSignerInfo, __out PSPROG_PUBLISHERINFO Info)
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
                    Logger::logf(Err, "CryptDecodeObject failed with %x @ Authenticode::GetProgAndPublisherInfo", GetLastError());
                    __leave;
                }

                // Allocate memory for SPC_SP_OPUS_INFO structure.
                OpusInfo = (PSPC_SP_OPUS_INFO)LocalAlloc(LPTR, dwData);
                if (!OpusInfo)
                {
                    Logger::logf(Err, "Unable to allocate memory for publisher info @ Authenticode::GetProgAndPublisherInfo");
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
                    Logger::logf(Err, "CryptDecodeObject failed with %x @ Authenticode::GetProgAndPublisherInfo", GetLastError());
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

/**
 * @brief Retrieves the time stamp signer information from a signer info structure
 *
 * @param pSignerInfo Structure representing information about the cert signer
 * @param pCounterSignerInfo Pointer to a pointer that will hold the counter signer info if found
 *
 * @return true/false if successfully retrieves the time stamp signer info
 *
 * @usage
 * PCMSG_SIGNER_INFO pCounterSignerInfo = NULL;
 * BOOL success = Authenticode::GetTimeStampSignerInfo(pSignerInfo, &pCounterSignerInfo);
*/
BOOL Authenticode::GetTimeStampSignerInfo(__in const PCMSG_SIGNER_INFO pSignerInfo, __out PCMSG_SIGNER_INFO* pCounterSignerInfo)
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
                    Logger::logf(Err, "CryptDecodeObject failed with %x @ Authenticode::GetTimeStampSignerInfo", GetLastError());
                    __leave;
                }

                // Allocate memory for CMSG_SIGNER_INFO.
                *pCounterSignerInfo = (PCMSG_SIGNER_INFO)LocalAlloc(LPTR, dwSize);
                if (!*pCounterSignerInfo)
                {
                    Logger::logf(Err, "Unable to allocate memory for timestamp info @ Authenticode::GetTimeStampSignerInfo");
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
                    Logger::logf(Err, "CryptDecodeObject failed with %x @ Authenticode::GetTimeStampSignerInfo", GetLastError());
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

/**
* @brief Retrieves the subject name of a certificate context
* @param pCertContext Pointer to the certificate context
* @return A wide string containing the subject name, or an empty string if an error occurs
* @usage
* wstring subjectName = Authenticode::GetCertificateSubject(pCertContext);
*/
std::wstring Authenticode::GetCertificateSubject(__in const PCCERT_CONTEXT pCertContext)
{
    BOOL fReturn = FALSE;
    LPTSTR szName = NULL;
    DWORD dwData;

    dwData = pCertContext->pCertInfo->SerialNumber.cbData;

    // Get Issuer name size.
    if (!(dwData = CertGetNameString(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL, NULL, 0)))
    {
        Logger::logf(Err, "CertGetNameString failed @ GetCertificateSubject");
        goto end;
    }

    szName = (LPTSTR)LocalAlloc(LPTR, dwData * sizeof(TCHAR));     // Allocate memory for Issuer name.
    if (!szName) 
    {
        Logger::logf(Err, "Unable to allocate memory for issuer name @ GetCertificateSubject");
        goto end;
    }

    if (!(CertGetNameString(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL, szName, dwData)))    // Get Issuer name.
    {
        Logger::logf(Err, "CertGetNameString failed @ GetCertificateSubject");
        goto end;
    }

    LocalFree(szName);
    szName = NULL;

    if (!(dwData = CertGetNameString(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, NULL, 0)))     // Get Subject name size.
    {
        Logger::logf(Err, "CertGetNameString failed @ GetCertificateSubject");
        goto end;
    }

    szName = (LPTSTR)LocalAlloc(LPTR, dwData * sizeof(TCHAR));
    if (!szName)
    {
        Logger::logf(Err, "Unable to allocate memory for subject name @ GetCertificateSubject");
        goto end;
    }

    if (!(CertGetNameString(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, szName, dwData)))     // Get subject name
    {
        Logger::logf(Err, "CertGetNameString failed @ GetCertificateSubject");
        goto end;
    }

    return std::wstring(szName);

end:
    if (szName != NULL) LocalFree(szName);

    return {};
}

/*
 * @brief Retrieves the signer information from a signed file
 *
 * @param filePath The path to the signed file
 *
 * @return A wide string containing the subject name of the signer certificate, or an empty string if an error occurs
 *
 * @usage
 * wstring signer = Authenticode::GetSignerFromFile(L"myfile.exe");
 */
std::wstring Authenticode::GetSignerFromFile(__in const std::wstring& filePath)
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
        Logger::logf(Err, "CryptQueryObject failed with %x @ GetSignerFromFile", GetLastError());
        return {};
    }

    // Get signer information size.
    fResult = CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &dwSignerInfo);

    if (!fResult)
    {
        Logger::logf(Err, "CryptMsgGetParam failed with %x @ GetSignerFromFile", GetLastError());
        return {};
    }

    // Allocate memory for signer information.
    pSignerInfo = (PCMSG_SIGNER_INFO)LocalAlloc(LPTR, dwSignerInfo);

    if (!pSignerInfo)
    {
        Logger::logf(Err, "Unable to allocate memory for Signer Info @ GetSignerFromFile");
        return {};
    }

    // Get Signer Information.
    fResult = CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, (PVOID)pSignerInfo, &dwSignerInfo);

    if (!fResult)
    {
        Logger::logf(Err, "CryptMsgGetParam failed with %x @ GetSignerFromFile", GetLastError());
        return {};
    }

    // Get program name and publisher information from 
    // signer info structure.
    if (GetProgAndPublisherInfo(pSignerInfo, &ProgPubInfo))
    {
        //if (ProgPubInfo.lpszProgramName != NULL) //uncomment if you want to print any additional information
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
        Logger::logf(Err, "CertFindCertificateInStore failed with %x @ GetSignerFromFile", GetLastError());
        return {};
    }

    std::wstring SubjectCert = GetCertificateSubject(pCertContext);

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
    //Logger::log(LogType::Warning, "Failed to query file's digital signature @ GetSignerFromFile");

    return SubjectCert;
}
