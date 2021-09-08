#include <Windows.h>
#include <stdio.h>
#include <winternl.h>

#pragma comment(lib,"ntdll.lib")

//typedef NTSTATUS(__stdcall* NtQuerySystemInformationFuncType) (SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);


int main() {

	//load "ntdll.dll" to retrieve "NtQuerySystemInformation" function.
	//HMODULE hModule = LoadLibraryA("ntdll.dll");
	LoadLibraryA("..\\..\\ProcessHiderDLL\\Debug\\ProcessHiderDLL.dll");

	//NtQuerySystemInformationFuncType NtQuerySystemInformation = (NtQuerySystemInformationFuncType) GetProcAddress(hModule, "NtQuerySystemInformation");

	const bufferSize = 2048 * 2048;
	byte *processesBuffer = malloc(bufferSize);
	NTSTATUS status = NtQuerySystemInformation(SystemProcessInformation, (PVOID) processesBuffer, bufferSize, NULL);

	if (!NT_SUCCESS(status)) {
		printf("[!] Unable to get the system process information: %x\r\n", status);
		free(processesBuffer);
		return 1;
	}

	SYSTEM_PROCESS_INFORMATION* startOfProcessesBuffer = (SYSTEM_PROCESS_INFORMATION*) processesBuffer;

	printf("Process name: %s\r\n", ((SYSTEM_PROCESS_INFORMATION*) processesBuffer)->ImageName.Buffer);
	while (((SYSTEM_PROCESS_INFORMATION*)processesBuffer)->NextEntryOffset != 0) { //traverse the process list until we reach the end
		processesBuffer += (((SYSTEM_PROCESS_INFORMATION*) processesBuffer)->NextEntryOffset);
		printf("Process name: %ws\r\n", ((SYSTEM_PROCESS_INFORMATION*)processesBuffer)->ImageName.Buffer);
	}
	
	free(startOfProcessesBuffer);

	return 0;
}