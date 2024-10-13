//thanks to changeofpace for remapping method!
//Original self-remapping code project can be found at: https://github.com/changeofpace/self-remapping-code

#pragma once

#include <Windows.h>
#include "../Common/Logger.hpp"

#define EXPECTED_SECTIONS 6 //for spoofing number of sections at runtime, which can prevent attackers from traversing sections

//=============================================================================
// Public Interface
//=============================================================================
_Check_return_ BOOL RmpRemapImage(_In_ ULONG_PTR ImageBase);
