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
Searching for **wav** and grap the correct hex headers 52 49 46 46 xx xx xx xx 57 41 56 45 66 6D 74 20 , according to this, the xx xx xx xx is the file
size (little endian). so replacing the new headers we can see that somethins not right, here i was blocked but after some googling i found that the data keyword should be there in hex to identify data section, after i found it ( 64 61 74 61 ), i replaced it and it workkks. now you can here some beeping after playing the wav sound, that so familiar its a morse code, so i navigate to this website https://morsecode.world/international/decoder/audio-decoder-adaptive.html, upload the file, decode it which will give  "beepbopmorsecode" and wrap it to the flag format.

**Flag : n00bz{beepbopmorsecode}**

### Disk Golf

This chall is my favorite one on this ctf, because it tested my abilities in Filesystems understanding like ext4.
- **description** : Let's play some disk golf!
Nothing interesting so i started with analyzing file with file tool.

As we see it is a linux disk but damaged or has some filesystem journal recovery issue. Here i was stuck for about 30 min ( after mounting the disk fails ) trying to understand the journal recovery for ext4, but i get a result of how to fix this using a tool e2fsck, lets run it.

As we see there is some problems with the size, so i tought why not resizing the disk image to match the filesystem's reported size, but this is a bit of a workaround and should be done carefully. and that was the clue.

 The idea is to increase the size of the disk image file to accommodate the filesystem's expected size. Lets calculate it :
 12844795 blocks * 4096 bytes/block = 52616196096 bytes (approximately 52.6 GB) ( Note that 4096=4KO which is the size of ext4 inode block )
 after calculating the new size, lets change it on disk.
sudo truncate -s 52616196096 disk1.img

runnig this again sudo e2fsck -f disk1.img and the ext4 filesystem should be fixed, now lets mount it.
sudo mkdir -p /mnt/disk1
sudo mount -o loop,ro,noload disk1.img /mnt/disk1

Finally navigating to the mounting place, we get :







**Flag : n00bz{7h3_l0ng_4w41t3d_d15k_f0r3ns1c5}**
