---
title: 'Malwares Devlopement Series | Part 2 : Process Injection | DLL Injection'
published: 2024-07-14
description: ''
image: ''
tags: ['Malwares', 'CTF', 'Forensics', 'DFIR', 'RedTeam', 'BlueTeam', 'APT', 'Threat Hunting']
category: 'Malwares'
draft: false 
---

Hello guys, Lets begin with the first malware technique which isss DLL Injection. If you didn't check the plan of our walkthrough go to it : [Introduction](link.com)

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

# How DLL Injection Works ?

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

So as we said we start by attaching the target process and the way to do that is to open a handle to it

```cpp
#include <iostream>

int main() {
    std::cout << "Hello, world!" << std::endl;
    return 0;
}```


so after dow



