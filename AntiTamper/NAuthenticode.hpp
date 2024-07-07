#pragma once
#include <tchar.h>
#include <windows.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <mscat.h>
#include "../Logger.hpp"

#pragma comment (lib, "wintrust")

namespace Authenticode
{
	BOOL VerifyEmbeddedSignature(LPCWSTR pwszSourceFile);
	BOOL VerifyCatalogSignature(LPCWSTR filePath);
	BOOL HasSignature(LPCWSTR filePath);
}

