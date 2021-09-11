#include <Windows.h>
#include <stdio.h>
#include <winternl.h>

#pragma comment(lib,"ntdll.lib")


int main() {
	LoadLibraryA("..\\..\\ProcessHiderDLL\\Debug\\ProcessHiderDLL.dll");


	const bufferSize = 1 << 22;
	SYSTEM_PROCESS_INFORMATION*processesBuffer = (SYSTEM_PROCESS_INFORMATION*) malloc(bufferSize);
	int returnLength = 0;
	NTSTATUS status = NtQuerySystemInformation(SystemProcessInformation, (PVOID) processesBuffer, bufferSize, &returnLength);

	if (!NT_SUCCESS(status)) {
		printf("[!] Unable to get the system process information: %x.\r\n", status);
		free(processesBuffer);
		return 1;
	}

	printf("The actual size of the processes information requested is %d.\r\n", returnLength);

	SYSTEM_PROCESS_INFORMATION* startOfProcessesBuffer = processesBuffer;

	printf("Process name: %ws\r\n", processesBuffer->ImageName.Buffer);
	while (processesBuffer->NextEntryOffset != 0) { //traverse the process list until we reach the end
		processesBuffer = ((byte*) processesBuffer) + processesBuffer->NextEntryOffset;
		printf("Process name: %ws\r\n", processesBuffer->ImageName.Buffer);
	}
	
	free(startOfProcessesBuffer);

	return 0;
}