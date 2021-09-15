# ProcessHider

ProcessHider is a tool that allows hiding processes from 32-bit applications.

[ProcessHiderDLL.dll](ProcessHiderDLL/Debug/ProcessHiderDLL.dll) uses IAT Table hooking technique to replace (in 32-bit applications) [NtQuerySystemInformation function](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation) with a malicious function that removes requested process's entries from the array of _SYSTEM_PROCESS_INFORMATION structures returned by the original NtQuerySystemInformation function ([source code](ProcessHiderDLL/ProcessHiderDLL/main.c)).

[ProcessHiderInjector.exe](ProcessHiderInjector/Debug/ProcessHiderInjector.exe) injects a dll (that its path is given by the "user") into a process (that its PID is given by the "user").  
Using this injector, one can inject [ProcessHiderDLL.dll](ProcessHiderDLL/Debug/ProcessHiderDLL.dll) into a process that uses [NtQuerySystemInformation function](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation) to monitor processes, and thus hide the desired process ([source code](ProcessHiderInjector/ProcessHiderInjector/main.c)).

[ProcessList.exe](ProcessList/Debug/ProcessList.exe) is a simple program that prints the current processes  names. It is used to test the ProcessHider mechanism ([source code](ProcessList/ProcessList/main.c)).

## Demonstration

In the screenshots below we can see that after [ProcessHiderDLL.dll](ProcessHiderDLL/Debug/ProcessHiderDLL.dll) had been injected into Task Manager (with PID of 18692), "chrome.exe" entries disappeared.

### Before Injection:
![img](Demonstration/Before%20injection.png "Before Injection")

### After Injection:
![img](Demonstration/After%20injection.png "After Injection")

Note: In order to hide a process (in this case, "chrome.exe") from Task Manager, [ProcessHiderInjector.exe](ProcessHiderInjector/Debug/ProcessHiderInjector.exe) should be run as administrator.  
