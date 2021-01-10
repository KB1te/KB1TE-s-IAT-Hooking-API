#include "hook.h"


BOOL Hook::HOOK(LPCSTR toHook, LPVOID myFunction, LPCSTR modName, LPVOID hookedAddress)
{
	this->origFunc = GetProcAddress(GetModuleHandleA(modName), toHook);
	MODULEINFO	modInfo;
	HMODULE		hMod = GetModuleHandle(0);
	GetModuleInformation(GetCurrentProcess(), hMod, &modInfo, sizeof(MODULEINFO));
	ULONG		a;
	PIMAGE_IMPORT_DESCRIPTOR	pDesc = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(&modInfo.lpBaseOfDll, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &a);
	PIMAGE_THUNK_DATA		toRead, toChange;
	while (pDesc->Name) {
		toRead = (PIMAGE_THUNK_DATA)(&modInfo.lpBaseOfDll + pDesc->OriginalFirstThunk);
		toChange = (PIMAGE_THUNK_DATA)(&modInfo.lpBaseOfDll + pDesc->FirstThunk);
		if (_strcmpi(modName, (char *)pDesc->Name)) {
			while (toRead->u1.Function) {
				if (toRead->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
					PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)(&modInfo.lpBaseOfDll + toRead->u1.AddressOfData);
					if (_strcmpi(toHook, pName->Name)) {
						MEMORY_BASIC_INFORMATION memInfo;
						VirtualQuery(memInfo.BaseAddress, &memInfo, sizeof(MEMORY_BASIC_INFORMATION));
						VirtualProtect(memInfo.BaseAddress, memInfo.RegionSize, PAGE_READWRITE, &memInfo.Protect);
						toChange->u1.Function = (DWORD)(DWORD_PTR)myFunction;
						VirtualProtect(memInfo.BaseAddress, memInfo.RegionSize, memInfo.Protect, &memInfo.Protect);
						this->hookedAddress = &toChange->u1.Function;
						this->modName = (char *)pDesc->Name;
						return TRUE;
					}
					else {
						pName++;
					}
				}
				toRead++;
				toChange++;
			}
		}
		pDesc++;
	}

	return FALSE;
}


BOOL Hook::UnHook(Hook MyHook)
{
	
	MEMORY_BASIC_INFORMATION memInfo;
	VirtualQuery(memInfo.BaseAddress, &memInfo, sizeof(MEMORY_BASIC_INFORMATION));
	VirtualProtect(memInfo.BaseAddress, memInfo.RegionSize, PAGE_READWRITE, &memInfo.Protect);
	this->hookedAddress = this->origFunc;
	VirtualProtect(memInfo.BaseAddress, memInfo.RegionSize, memInfo.Protect, &memInfo.Protect);
	return TRUE;
					
}
