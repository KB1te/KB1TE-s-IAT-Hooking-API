#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <ImageHlp.h>
#include <psapi.h>
#include <iostream>

class Hook {
public:
	BOOL HOOK(HMODULE hMod, LPCSTR toHook, LPVOID myFunction, LPCSTR modName);
	BOOL HOOK(HMODULE hMod, LPCSTR toHook, LPVOID myFunction, LPCSTR modName, DWORD *hookedAddress);
	void PrintHookInfo(Hook *hookInfo);
private:
	DWORD *hookedAddress;
	LPCSTR modName;
	
};