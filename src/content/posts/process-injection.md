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


# what is a DLL ?

A DLL or Dynamic Link Libraries is a modules that contain functions and data that can be used by another module (process or DLL).

You didn't understand huh, I'll give you an example, Imagine a process like notepad.


Notepad, as a simple text editor, relies on several standard Windows DLLs. Here are some of the common ones you might see:

```kernel32.dll```: It's an important one that we will encounter many times, It provides core operating system functionalities, such as memory management, input/output operations, and process and thread creation.

```user32.dll```: It contains functions for handling user interface components like windows, menus, and user input.

```gdi32.dll```: This one handles graphics device interface (GDI) functions for drawing graphics and text.





