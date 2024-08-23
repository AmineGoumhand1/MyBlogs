---
title: 'Malwares Development Series | Part 4 : Process Injection | TLS Injection'
published: 2024-08-16
description: ''
image: ''
tags: ['Malwares', 'CTF', 'Forensics', 'DFIR', 'RedTeam', 'BlueTeam', 'APT', 'Threat Hunting']
category: 'Malwares'
draft: false 
---
![Back](/favicon/malwwware.jpg)

Welcome back to a new Process Injection technique : Thread Local Storage Injection where i'll cover its implementation and how it works.
During this blog, we'll follow this plan :

- **What is TLS Injection ?**
- **How TLS Injection works ?**
- **TLS Injection Implementation**

Lets start!

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

Form of .tls section :

|-----------------------------|
|  TLS Directory              |
|-----------------------------|
|  TLS Callbacks Array        |
|-----------------------------|
|  TLS Data                   |

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

- **StartAddressOfRawData**
This field contains !the Relative Virtual Address `RVA` of the beginning of the TLS data in the PE file.

- **EndAddressOfRawData**
This field contains the `RVA` of the end of the TLS data in the PE file.

- **AddressOfIndex**
This points to a location where the thread-specific TLS index is stored. This index is used by the operating system to reference the TLS data for each thread.

- **AddressOfCallBacks**
This is the address of an array of pointers to TLS callback functions. These functions are called by the operating system during specific events, such as thread creation or exit.

- **SizeOfZeroFill**
This field specifies the size of the area to be zeroed out in the TLS data section. It’s used for initializing TLS data with zeros.

This TLS Directory is a key structure within the .tls section because it provides these necessary information for the operating system to manage TLS data for each thread.

Next structure in the .tls section is the TLS callbacks, which is an array of function pointers that the operating system automatically invokes at specific times in the lifecycle of a thread. These callbacks are used for initializing or cleaning up thread-specific data.. 
This arrays is null-terminated, meaning that the last pointer in the array is a NULL pointer. 

```cpp
PIMAGE_TLS_CALLBACK tls_callbacks[] = {
    CallbackFunction1,
    CallbackFunction2,
    // ... more callbacks
    NULL  // End of the array
};
```
The array is stored at the address specified by the `AddressOfCallBacks` field in the `IMAGE_TLS_DIRECTORY` structure. Each entry in the array points to a callback function that will be invoked during certain thread events.









