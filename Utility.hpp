#pragma once
#include <stdint.h>
#include <Windows.h>

class Utility
{
public:
	
	template<class T>
	static T ReadPointer(uint64_t ulBase, uint64_t ulOffset)
	{
		__try
		{
			return *(T*)(*(uint64_t*)ulBase + ulOffset);
		}
		__except (1) { return (T)NULL; }
	}

	template<class T>
	static bool WritePointer(uint64_t ulBase, uint64_t ulOffset, T iValue)
	{
		__try { *(T*)(*(uint64_t*)ulBase + ulOffset) = iValue; return true; }
		__except (1) { return false; }
	}

	template<class T>
	static T DereferenceSafe(uint64_t ulAddress)
	{
		__try
		{
			return *(T*)ulAddress;
		}
		__except (1) { return (T)NULL; }
	}

	template<class T>
	static inline void** GetVTableArray(T* pClass, int* pSize) //thanks to  https://stackoverflow.com/questions/2705927/get-specific-process-memory-space
	{
		void** ppVTable = *(void***)pClass;

		if (pSize)
		{
			*pSize = 0;

			while (!IsBadReadPtr(ppVTable[*pSize], sizeof(unsigned __int64)))
				(*pSize)++;
		}

		return ppVTable;
	}

	static bool IsVTableHijacked(void* pClass);
};
