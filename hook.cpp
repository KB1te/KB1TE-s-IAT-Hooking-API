#include "hook.h"


BOOL Hook::HOOK(LPCSTR toHook, LPVOID myFunction)
{
	this->origFunc = GetProcAddress(GetModuleHandleA(modName), toHook);
	DWORD				oldProc	= NULL;
	HMODULE				hModule = GetModuleHandleA(NULL);
	MODULEINFO			ModInfo = { NULL };
	PIMAGE_DOS_HEADER		pDos    = { NULL };
	PIMAGE_NT_HEADERS		pNt     = { NULL };
	PIMAGE_IMPORT_DESCRIPTOR	pDesc   = { NULL };
	PIMAGE_THUNK_DATA		change  = { NULL };
	PIMAGE_THUNK_DATA		read    = { NULL };
	PIMAGE_IMPORT_BY_NAME		pName	= { NULL };

	GetModuleInformation(GetCurrentProcess(), hModule, &ModInfo, sizeof(ModInfo)); 
	pDos = (PIMAGE_DOS_HEADER)(ModInfo.lpBaseOfDll); 
	pNt = (PIMAGE_NT_HEADERS)((DWORD_PTR)ModInfo.lpBaseOfDll + pDos->e_lfanew);
	pDesc = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)ModInfo.lpBaseOfDll + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	while(pDesc->OriginalFirstThunk) {
		read = (PIMAGE_THUNK_DATA)((DWORD_PTR)ModInfo.lpBaseOfDll + pDesc->OriginalFirstThunk);
		change = (PIMAGE_THUNK_DATA)((DWORD_PTR)ModInfo.lpBaseOfDll + pDesc->FirstThunk);
		while(read->u1.Function) {
			pName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)ModInfo.lpBaseOfDll + read->u1.AddressOfData);
			if (_strcmpi(pName->Name,toHook)) {
				VirtualProtect((LPVOID)change->u1.Function, sizeof(LPVOID), PAGE_EXECUTE_READWRITE, &oldProc);
				change->u1.Function = myFunction;
				VirtualProtect((LPVOID)change->u1.Function, sizeof(LPVOID), oldProc, NULL);
			}
			else {
				pName++;
			}
			read++, change++;
		}
		pDesc++;
	}
	return FALSE;
}


BOOL Hook::UnHook(Hook MyHook)
{
	DWORD old = NULL;
	VirtualProtect(this->hookedAddress, sizeof(LPVOID), PAGE_EXECUTE_READWRITE, &old);
	this->hookedAddress = this->origFunc;
	VirtualProtect(this->hookedAddress, sizeof(LPVOID), old, NULL);
	return TRUE;
					
}
