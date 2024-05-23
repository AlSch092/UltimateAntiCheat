//thanks to changeofpace for remapping method
#pragma once

#include <Windows.h>
#include "../Logger.hpp"
//=============================================================================
// Public Interface
//=============================================================================
_Check_return_
BOOL
RmpRemapImage(
    _In_ ULONG_PTR ImageBase
);
