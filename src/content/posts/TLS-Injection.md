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

So until now, we defined the TLS, lets get familiarized with TLS Callbacks.

One of the advanced features of TLS in Windows is the ability to specify TLS callbacks. TLS callbacks are special functions that are automatically called by the operating system at specific points in the lifetime of a thread. For example lets take the main ones :

- **DLL Load**: In this case, when a DLL is loaded, and a thread is created, the TLS callback is invoked.
- **Thread Creation**: When a new thread is created within the process, the TLS callback is invoked for that thread.
- **Thread Exit**: Also when a thread exits, the TLS callback is invoked to clean up any TLS data.
- **DLL Unload**: When the DLL is unloaded, the TLS callback is invoked.

These are the main actions when a TLS callback is called. Now, the most question that might be confusing you is Where these callbacks can be ?. Well The PE structure is the key to this one.

As I mentioned in the previous blog, a PE format is the file format for executables, object code, and DLLs in Windows operating systems. The PE file format is a data structure that encapsulates the information necessary for the Windows OS loader to manage the wrapped executable code.

You can refer to the previous blog for more infos. So almost of windows related files are PE, and TLS has a specific section on this PE files which is .tls that define and manage variables that are unique to each thread in a process as we said before.
So lets uncover this TLS section to know more.

- **.tls section**:












