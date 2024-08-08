//thanks to changeofpace for remapping method
#pragma once

#include <Windows.h>
#include "../Common/Logger.hpp"

#define EXPECTED_SECTIONS 6

//=============================================================================
// Public Interface
//=============================================================================
_Check_return_ BOOL RmpRemapImage(_In_ ULONG_PTR ImageBase);
