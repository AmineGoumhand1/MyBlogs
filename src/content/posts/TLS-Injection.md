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

First what a TLS ?

Thread Local Storage or (TLS) is a mechanism that allows threads within the same process to have their own unique data. 
Unlike global or static variables that are shared across all threads, TLS provides a way for each thread to have its own copy of a variable, enabling thread-specific storage. This is particularly useful in multithreaded applications where each thread needs to maintain its own state or data, independent of other threads.

So what we really should is that in Windows, TLS is implemented using the operating system's support for threading. When a thread is created, it is allocated its own TLS area, which can store variables that are unique to that thread. 
So the system manages the allocation and cleanup of TLS data automatically as threads are created and destroyed.

So until now, we defined the TLS, so lets get familiarized with TLS Callbacks.

One of the advanced features of TLS in Windows is the ability to specify TLS callbacks. TLS callbacks are special functions that are automatically called by the operating system at specific points in the lifetime of a thread:

- **DLL Load**: When the DLL is loaded, and a thread is created, the TLS callback is invoked.
- **Thread**: Creation: When a new thread is created within the process, the TLS callback is invoked for that thread.
- **Thread Exit**: When a thread exits, the TLS callback is invoked to clean up any TLS data.
- **DLL Unload**: When the DLL is unloaded, the TLS callback is invoked.






