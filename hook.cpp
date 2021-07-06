#include <Windows.h>
#include <Psapi.h>

int main(void) {
	HMODULE	hModule = GetModuleHandleA("user32.dll");
	MODULEINFO ModInfo = { NULL };
	GetModuleInformation(GetCurrentProcess(), hModule, &ModInfo, sizeof(ModInfo));
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((int *)ModInfo.lpBaseOfDll + 0x3C);
	PIMAGE_IMPORT_DESCRIPTOR pDesc = (PIMAGE_IMPORT_DESCRIPTOR)((int *)ModInfo.lpBaseOfDll + 0x168);
	for (; pDesc->OriginalFirstThunk; pDesc++) {
		PIMAGE_THUNK_DATA read = (PIMAGE_THUNK_DATA)((int *)ModInfo.lpBaseOfDll + pDesc->OriginalFirstThunk);
		PIMAGE_THUNK_DATA change = (PIMAGE_THUNK_DATA)((int *)ModInfo.lpBaseOfDll + pDesc->FirstThunk);
		for (; read->u1.Function; read++, change++) {
			PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)((int *)ModInfo.lpBaseOfDll + read->u1.AddressOfData);
			if (_strcmpi(pName->Name, "MessageBoxA")) {
				int oldProc = 0;
				VirtualProtect((LPVOID)change->u1.Function, sizeof(LPVOID), PAGE_EXECUTE_READWRITE, (PDWORD)&oldProc);
				change->u1.Function = 0;
				VirtualProtect((LPVOID)change->u1.Function, sizeof(LPVOID), oldProc, NULL);
			}
		}
	}
	return 0;
}
