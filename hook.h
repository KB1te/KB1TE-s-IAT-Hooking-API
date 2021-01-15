#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <ImageHlp.h>
#include <psapi.h>
#include <iostream>

class Hook {
public:
	BOOL HOOK(LPCSTR toHook, LPVOID myFunction);
	BOOL UnHook(Hook MyHook);
	
private:
	DWORD *hookedAddress;
	LPCSTR modName;
	LPVOID origFunc;

};
