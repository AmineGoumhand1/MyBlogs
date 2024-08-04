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

We are given an image of a plane, so the first thing I did is looking at the metadata of the image using exiftool.
![ ](/favicon/plane1.png)
As we are seeing, there is some coordinates there, except they are in `degrees, minutes, and seconds (DMS)`. Lets convert those to decimal `degrees (DD)` :

**Latitude**
13 degrees, 22 minutes, 12 seconds North

Convert to decimal degrees:

DD=degrees+(minutes/60)+(seconds/3600)

So,
```
DDLatitude=13+(22/60)+(12/3600)
DDLatitude=13+0.3667+0.0033
DDLatitude≈13.3700
```
Since it is North, the sign remains positive.

**Longitude**
13 degrees, 22 minutes, 12 seconds West

Same calculations, I found :
```
DDLatitude≈-13.3700
```
Since it is West, the sign is negative.

**Final Coordinates**
`Latitude: 13.3700`
`Longitude: -13.3700`


**Flag : n00bz{13.37,-13.37}**

### Wave

- **description** : The Wave is not audible, perhaps corrupted? Note: Wrap the flag in n00bz{}. There are no spaces in the flag and it is all lowercase.

As we heard in the description, "perhaps corrupted",so i looked to the hex headers with hexedit, and yes there is some missed up values that needs fixing. ( those highlighted by green color like `3030 sequences` seems to be incorrect ).
![wave](/favicon/wavve.png)
How? I took my browser to the famous hex headers website : [GaryKessler](https://garykessler.net/)
Searching for **wav** and grap the correct hex headers `52 49 46 46 xx xx xx xx 57 41 56 45 66 6D 74 20`.
According to this, the `xx xx xx xx` is the file size (little endian). So replacing the new headers we can see that somethins not right, here i was blocked but after some googling i found that the `data` chunk keyword should be there in hex to identify data section, after i found it `64 61 74 61`, i replaced it and it workkks. 

I can hear some beeping after playing the wav sound, that so familiar its a morse code, so i took my self to this website [morsecode](https://morsecode.world/international/decoder/audio-decoder-adaptive.html), upload the file, decode it which will give  `beepbopmorsecode` and wrap it to the flag format.

**Flag : n00bz{beepbopmorsecode}**

### Disk Golf

This chall is my favorite one on this ctf, because it tested my abilities in Filesystems understanding like ext4.

- **description** : Let's play some disk golf!

Nothing interesting so i started with analyzing file with `file` tool.
```
file disk1.img
--> disk1.img: Linux rev 1.0 ext4 filesystem data, UUID=7b1c29f0-7159-4456-9ca8-db40f35bc6ff, volume name "cloudimg-rootfs" (needs journal recovery)  (extents) (64bit) (large files) (huge files)                 
```
As we see it is a linux disk but damaged or has some filesystem journal recovery issue. Here i was stuck for about 30 min ( after mounting the disk fails ) trying to understand the journal recovery for ext4, but i got a result of how to fix this using a tool e2fsck, lets run it.
![image](/favicon/golf1.png)
As we see there is some problems with the size, so i tought why not resizing the disk image to match the filesystem's reported size, but this is a bit of a workaround and should be done carefully. and that was the clue.

 The idea is to increase the size of the disk image file to accommodate the filesystem's expected size. Lets calculate it :
 `12844795 blocks * 4096 bytes/block = 52616196096 bytes` (approximately 52.6 GB) ( Note that 4096=4KO which is the size of ext4 inode block )
 after calculating the new size, lets change it on disk.
 
```bash
sudo truncate -s 52616196096 disk1.img
```
Now lets run `e2fsck` to fix the filesystem.

```bash
sudo e2fsck -f disk1.img
```
![image](/favicon/golf3.png)

lets re-mount it.
```bash
sudo mkdir -p /mnt/disk1
sudo mount -o loop,ro,noload disk1.img /mnt/disk1
```
Finally navigating to the mounting place, we get :
![first](/favicon/first.png)
Opening the john doe folder,
![fourth](/favicon/fourth.png)
We can see that there is two txt docs named flag1 and 2, the flag2 is just fake one, the flag1 is an octal base encoding.
`156 60 60 142 172 173 67 150 63 137 154 60 156 147 137 64 167 64 61 164 63 144 137 144 61 65 153 137 146 60 162 63 156 163 61 143 65 175`
Passing it to Cyberchef and I got the flag.


**Flag : n00bz{7h3_l0ng_4w41t3d_d15k_f0r3ns1c5}**


# Crypto

### Vinegar

- **description** : Can you decode this message? Note: Wrap the decrypted text in n00bz{}.

This is a simple challenge to decrypt a given vigénere cipher with a given key.
"Encrypted flag :" nmivrxbiaatjvvbcjsf
"Key :" secretkey

You can use dcode.fr to decode it.

**Flag : n00bz{vigenerecipherisfun}**

### RSA

- **description** : The cryptography category is incomplete without RSA. So here is a simple RSA challenge. Have fun!.
Given : e, c and n.

Another classic challenge implementing the cube root attack ( rsa ), because as we see the e is too small.

```python
from sympy import Integer, real_root

# Given values
e = 3
c = 13037717184940851534440408074902031173938827302834506159512256813794613267487160058287930781080450199371859916605839773796744179698270340378901298046506802163106509143441799583051647999737073025726173300915916758770511497524353491642840238968166849681827669150543335788616727518429916536945395813

# Compute the cube root of the ciphertext
m = real_root(Integer(c), e)

# Convert the SymPy Integer to a native Python int
m_int = int(m)

# Convert the integer to bytes
m_bytes = m_int.to_bytes((m_int.bit_length() + 7) // 8, byteorder='big')

# Convert bytes to a string if it represents text
try:
    decrypted_message = m_bytes.decode('utf-8')
except UnicodeDecodeError:
    decrypted_message = m_bytes

print(f"Decrypted message (as integer): {m_int}")
print(f"Decrypted message (as bytes): {m_bytes}")
print(f"Decrypted message (as text): {decrypted_message}")
```

**Flag : n00bz{crypt0_1s_1nc0mpl3t3_w1th0ut_rs4!!}**

### Vinegar2

This is like a revenge for the first vinegar chall but still easy.

- **description** : Never limit yourself to only alphabets! .
from the description we know that we are dealing with numbers and chars too, so lets analyze the given code together.

```python
alphanumerical = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*(){}_?'
matrix = []
for i in alphanumerical:
	matrix.append([i])

idx=0
for i in alphanumerical:
	matrix[idx][0] = (alphanumerical[idx:len(alphanumerical)]+alphanumerical[0:idx])
	idx += 1

flag=open('../src/flag.txt').read().strip()
key='5up3r_s3cr3t_k3y_f0r_1337h4x0rs_r1gh7?'
assert len(key)==len(flag)
flag_arr = []
key_arr = []
enc_arr=[]
for y in flag:
	for i in range(len(alphanumerical)):
		if matrix[i][0][0]==y:
			flag_arr.append(i)

for y in key:
	for i in range(len(alphanumerical)):
		if matrix[i][0][0]==y:
			key_arr.append(i)

for i in range(len(flag)):
	enc_arr.append(matrix[flag_arr[i]][0][key_arr[i]])
encrypted=''.join(enc_arr)
f = open('enc.txt','w')
f.write(encrypted)
```

The key to the flag is to recognize that the cipher using a matrix of alphanumeric characters. The matrix is constructed by generating cyclic permutations of a predefined set of characters, which includes letters, digits, and special symbols. Each row of the matrix starts with a different character from this set, followed by a rotation of the remaining characters. 
So we can reverse this process by reconstructing the matrix and reversing the index-based substitution to recover the original flag.

So reversing it will give us the flag.
```python
alphanumerical = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*(){}_?'
matrix = []
for i in alphanumerical:
    matrix.append([i])
idx = 0
for i in alphanumerical:
    matrix[idx][0] = (alphanumerical[idx:len(alphanumerical)] + alphanumerical[0:idx])
    idx += 1
encrypted = '*fa4Q(}$ryHGswGPYhOC{C{1)&_vOpHpc2r0({'
key = '5up3r_s3cr3t_k3y_f0r_1337h4x0rs_r1gh7?'
flag_arr = []
key_arr = []
dec_arr = []
for y in key:
    for i in range(len(alphanumerical)):
        if matrix[i][0][0] == y:
            key_arr.append(i)
for i in range(len(encrypted)):
    enc_char = encrypted[i]
    key_idx = key_arr[i]
    enc_row = matrix[key_idx][0]
    
    for j in range(len(enc_row)):
        if enc_row[j] == enc_char:
            flag_arr.append(j)
            break
for idx in flag_arr:
    dec_arr.append(alphanumerical[idx])
flag = ''.join(dec_arr)
print(flag)
```

**Flag : n00bz{4lph4num3r1c4l_1s_n0t_4_pr0bl3m}**

# OSINT

The organizers putted some really good osint challenges. But still unable to solve them all, anyway we managed to solve the first 3.

### Tail

- **description** : Here's a picture of a plane's tail. Can you find the airline's hub (the airport where they mostly operate from). Use the three letter airport IATA code and wrap it in n00bz{}. Example: n00bz{SFO}.

So first thing i tried here is to google this image, but google gives me some shitty results like Sonic speed .. After some manual googling about plane tails i found this interesting photographer [website](https://airlinersgallery.smugmug.com/Airline-Tails/Airline-Tails) that loves taking pictures of plane tails, there are a lot of Tails so i started by checking one by one till i found the one that matches the given image.
![image](/favicon/tail1.png)
As we can see, it is for "Air Tahiti Nui" Airlines. so lets grap the Airport code from the IATA official [website](https://www.iata.org/en/publications/directories/code-search/?airport.search=Air%20Tahiti%20Nui), searching by "Air Tahiti Nui".
![image](/favicon/tahiti.png)

And we found it ( Cityname : Tahiti and code : PPT )

**Flag : n00bz{PPT}**

### Gang

- **description** : John Doe has been suspected of creating a gang. The members of team n00bzUnit3d also seem associated with it. Can you find out if John Doe has recently joined the team? You might find what you are looking for ;) P.S.: The team website might help.

So after reading the description, we know that we are looking for a member of the n00bzUnit3d team, so discovering their website,
![image](/favicon/osint2.png)

Navigating to the Members section, I noticed John Doe name when i hovered on the last profile. So I discovered this profile and i got the flag.
![image](/favicon/tail1.png)
![image](/favicon/osint222.png)

**Flag : n00bz{1ts_051N7_71m3_3e4a7d6f}**

### Pastebin

- **description** :Just go to my pastebin which was created long time back.
Important!
There have been some changes to this challenge due things outside our control (like deletion of the pastebin). The above description is still valid (and so is the original info), but you will need the new info to solve the challenge now. Challenge is still solvable. Author: noob_abhinav
Note:- https://pastebin.com/u/abhinav654321 New info:- https://pastebin.com/j1UnKA7m

So before the hints were there, we have only the first line and the link to the pastebin [website](https://pastebin.com/u/abhinav654321),

atfer i discovered this one, i found nothing, just some comments that hints to some deleted content, so i combined this with the description `was created long time back.` and i was sure that is a wayback machine challenge, so i graped the pastebin website and wayback it and I was able to retreive the deleted content.

**Flag : n00bz{l0ng_t1m3_ag0_m34ns_w4yb4ck}**










