---
title: 'CTF Write-Ups : n00bz CTF'
published: 2024-08-03 
description: ''
image: ''
tags: ['CTF', 'DFIR', 'Forensics' , 'Crypto' , 'OSINT' , 'Reverse' , 'Web']
category: 'CTF'
draft: false 
---
Welcome. In this blog, I'll cover some challenges from the n00bz ctf that i participated in with my team 0M3G4_SQU4D.

## Challenges

| Category         | Name / Points   | 
|------------------|--------|
| Forensics  | Plane 200pts  
| Forensics  | Wave 446   | 
| Forensics | disk golf 495 |
| OSINT                 | Tail 216       | 
|   OSINT               |     The Gang 246   | 
|     OSINT              |    Pastebin 400    | 
| Misc | Additions 318pts |
| Misc | Sanity check 100pts |
| Misc | Subtraction |
| Web | Passwordless 162pts |
| Reverse | Vacation 250pts |
| Reverse | Brain 426pts |
| Crypto | Vinegar 100pts |
| Crypto | Vinegar2 |
| Crypto | Rsa |
| Programming | Sillygoos |
| Programming | Numbers2 |




# Forensics

### Plane

- **description** : So many plane-related challenges! Why not another one? The flag is the latitude, longitude of the place this picture is taken from, rounded upto two decimal places. Example: n00bz{55.51,-20.27}.

We are given an image of a plane, so the first thing I did is to look at the metadata of the image using exiftool.
![image]()
As we are seeing, there is some coordinates there, except they are in degrees, minutes, and seconds (DMS). Lets convert it to decimal degrees (DD):

**Latitude**
13 degrees, 22 minutes, 12 seconds North

Convert to decimal degrees:

DD=degrees+(minutes/60)+(seconds/3600)

So,
DDLatitude=13+(22/60)+(12/3600)
DDLatitude=13+0.3667+0.0033
DDLatitude≈13.3700

Since it is North, the sign remains positive.

**Longitude**
13 degrees, 22 minutes, 12 seconds West

Same calculations, we find :

DDLatitude≈-13.3700

Since it is West, the sign is negative.

**Final Coordinates**
Latitude: 13.3700
Longitude: -13.3700


**Flag : n00bz{13.37,-13.37}**

### Wave

- **description** : The Wave is not audible, perhaps corrupted? Note: Wrap the flag in n00bz{}. There are no spaces in the flag and it is all lowercase.
As we heard in the description, "perhaps corrupted", so i looked to the hex headers with hexedit, and yes there is some missed up values that needs fixing.
How? I took my browser to the famous hex headers website : garykessler.net/
Searching for **wav** and grap 
