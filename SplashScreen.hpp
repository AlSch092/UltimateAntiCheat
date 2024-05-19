#pragma once
#include <windows.h>
#include <gdiplus.h>
#include <iostream>
#include "Logger.hpp"

#pragma comment(lib, "gdiplus.lib")

using namespace Gdiplus;

namespace Splash
{
	static const wchar_t* SplashImageName = L"splash.png";

	static ULONG_PTR gdiplusToken;
	static LRESULT CALLBACK SplashWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
	static HWND CreateSplashWindow(HINSTANCE hInstance);
	static void PositionWindow(HWND hwnd);
	void InitializeSplash();
}