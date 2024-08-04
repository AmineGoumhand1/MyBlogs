---
title: 'CTF Write-Ups : n00bz CTF 2024'
published: 2024-08-03 
description: ''
image: ''
tags: ['CTF', 'DFIR', 'Forensics' , 'Crypto' , 'OSINT' , 'Reverse' , 'Web']
category: 'CTF'
draft: false 
---
![](/favicon/dashboard1.png)
### Welcome. In this blog, I'll cover some challenges from the n00bz ctf that i participated in with my team 0M3G4_SQU4D.

# Solved Challenges

<style>
  .category {
    font-weight: bold;
    color: white;
  }
  .forensics {
       font-weight: bold;

    color: #0FF641 ;
    border-radius: 8px;
    padding: 5px;
    margin: 2px;
  }
  .osint {
	      font-weight: bold;

    color: #0FF641;
    border-radius: 8px;
    padding: 5px;
    margin: 2px;
  }
  .misc {
	      font-weight: bold;

    color: #0FF641;
    border-radius: 8px;
    padding: 5px;
    margin: 2px;
  }
  .web {
	      font-weight: bold;

    color: #0FF641;
    border-radius: 8px;
    padding: 5px;
    margin: 2px;
  }
  .reverse {
	      font-weight: bold;

    color: #0FF641;
    border-radius: 8px;
    padding: 5px;
    margin: 2px;
  }
  .crypto {
	      font-weight: bold;

    color: #0FF641;
    border-radius: 8px;
    padding: 5px;
    margin: 2px;
  }
  .programming {
	      font-weight: bold;

    color: #0FF641;
    border-radius: 8px;
    padding: 5px;
    margin: 2px;
  }
  .blockchain {
	      font-weight: bold;

    color: #0FF641;
    border-radius: 8px;
    padding: 5px;
    margin: 2px;
  }
</style>
 Category         | Name | Points        | 
------------------|------|---------------|
<span class="category forensics">Forensics</span> | Plane | 100pts  
<span class="category forensics">Forensics</span> | Wave | 391pts  
<span class="category forensics">Forensics</span> | Disk Golf | 464pts  
<span class="category osint">OSINT</span> | Tail | 100pts  
<span class="category osint">OSINT</span> | The Gang | 100pts  
<span class="category osint">OSINT</span> | Pastebin | 285pts  
<span class="category osint">OSINT</span> | Gang2 | 425pts  
<span class="category osint">OSINT</span> | Gang3 | 490pts  
<span class="category misc">Misc</span> | Additions | 121pts  
<span class="category misc">Misc</span> | Sanity Check | 100pts  
<span class="category misc">Misc</span> | Subtraction | 453pts  
<span class="category web">Web</span> | Passwordless | 100pts  
<span class="category web">Web</span> | Focus on yourSELF | 436pts  
<span class="category web">Web</span> | File Sharing Portal | 483pts  
<span class="category reverse">Reverse</span> | Vacation | 250pts  
<span class="category reverse">Reverse</span> | Brain | 426pts  
<span class="category reverse">Reverse</span> | FlagChecker | 426pts  
<span class="category crypto">Crypto</span> | Vinegar | 100pts  
<span class="category crypto">Crypto</span> | Vinegar2 | 165pts  
<span class="category crypto">Crypto</span> | RSA | 100pts  
<span class="category crypto">Crypto</span> | Random | 454pts  
<span class="category programming">Programming</span> | Sillygoos | 274pts  
<span class="category programming">Programming</span> | Numbers2 | 416pts  
<span class="category blockchain">Blockchain</span> | EVM | 372pts  
<span class="category blockchain">Blockchain</span> | EVM: Conditions | 462pts

I'll cover the challenges that i solved. maybe some of my friends.

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

The organizers putted some really good osint challenges. But still unable to solve them all, anyway we managed to solve 5.

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
![image](/favicon/osint222.png)

**Flag : n00bz{1ts_051N7_71m3_3e4a7d6f}**

### Pastebin

- **description** : Just go to my pastebin which was created long time back.
Important!
There have been some changes to this challenge due things outside our control (like deletion of the pastebin).
The above description is still valid (and so is the original info), but you will need the new info to solve the challenge now.
Challenge is still solvable.

Note:- https://pastebin.com/u/abhinav654321 | New info:- https://pastebin.com/j1UnKA7m

So before the hints were there, we have only the first line and the link to the pastebin [website](https://pastebin.com/u/abhinav654321),

atfer i discovered this one, i found nothing, just some comments that hints to some deleted content, so i combined this with the description `was created long time back.` and i was sure that is a wayback machine challenge, so i graped the pastebin website and wayback it and I was able to retreive the deleted content.
![](/favicon/osint3.png)

**Flag : n00bz{l0ng_t1m3_ag0_m34ns_w4yb4ck}**

### Gang2
- **description** : You may have gotten your first flag, but it's just the beginning! John Doe, as overconfident as he is, has left you with a riddle. Maybe it hides some secrets? Continue where you left off last time. Flag will already by wrapped in n00bz{} .

So continuing from the members website, we can see the riddle 
![](/favicon/riddle.png)
Here i was stuck a bit but i noticed the first capitale char of each line, so join them will give USERNAME IS JOHN HACKER DOE, Emmmm, so i start searching for this on google but with no result, i toke it to W (twitter) and i found it, it's an account. Exploring the posts, and i got the flag 
![](/favicon/riddle3.png)

**Flag : n00bz{5t0p_ch4s1ng_m3_4f2d1a7d}**

### Gang3
- **description** : Can you find out where the OG meetup point is? The flag is in the format n00bz{lat,long} with upto 3 decimal places, rounded. Continue where you left off... Note: Wikipedia can be wrong sometimes ;) .

Continuing on the Gang2 chall.
we can see there is some sort of encrypted communication guiding in the account.

```
Wanna join us? I have a challenge for you:

The ciphertext (using AES-GCM) is: 1762841d1888f6b02581990abdf0aaba375c85fd3811a6fb405775fb8d + the key is the same as last time and the IV is "Lat,Long" up to 3 decimal places.
Use the city where we met in 2022. Also, use Cyberchef. I forgot, you will also need this: d5e749da6b02c75cb4c763939632503a
```

So we have an encrypted text with aes-gcm , which needs a tag (d5e749da6b02c75cb4c763939632503a) that they give us, for the iv `the city where we met in 2022` i tought why not to look at some n00bz previous events of ctfs and i found a [github](https://github.com/n00bzUnit3d) repo that contains their official write-ups ( specially 2022 write-up ).

Seems like john doe still appear in these osint challs too , so i took a look and found a city with a flag that contains the location (alt,lon) which is 46.720_33.154. I'll let you explore it. 
So convert this ( 46.720,33.154 ) to hex and we should get `34 36 2E 37 32 30 2C 33 33 2E 31 35 34`.

Now lets search for the key, from the discription we have that they used this key before so returning back to the github repo and found nothing else in 2022 event, so i explored osint 2023 and i found this :

```
Description - John Doe has escaped our high secruity prison again! We managed to intercept an xor key that he uses to send encrypted messages to people! Your aim is to find classified information on his top secret website! Start with the encrypted message -
 b'\x13\x00\x1d-A*!\x00Q\x16R\x02\x12\x07\n\x1b>\x0e\x06\x1a~O-D CU\t\x0e\x06 E2\n\x17bA#\x0b\t>O\x11\x011O\tH*\x1b\x10-\x08\x00)E\x02\nMck~)\x07"\x01H*+\n_\x01\x00\x00\x00c\n\x00!\x12V\r\x1d4A\x19\x16\x0b"O!N(\x00\x13Dy\x02\x000\x08\rn\x16\x19E\x16,\x0fS\x17H+\x1c\x03N)\nEU1\x0e\x01c\x10\x1b+\x16\x02\x0c\x1d-A\x11\x15\r8\x16H\x0f#\x0e\x0cOx'
and the secret key - YouCanNeverCatchJohnDoe!. We also intercepted the name of his account - 31zdugxvkayexc4hzqhixxcfxb4y
```
I got the keyyy, its `YouCanNeverCatchJohnDoe!`, convert it to hex to get `596f7543616e4e6576657243617463684a6f686e446f6521`.
Lets decrypt these now on CyberChef as they said.
![](/favicon/riddle4.png)

we got a discord server, `https://discord.gg/9v2FEjndCb`. 
I explored it to find some sort of communication about the meeting place of the OG (Original Gangster). 
By identifying what they are saying, you can conclude that the meeting was in the `Statue of Prosparity`. and we finally search for its location on the mentioned airport, after i searched on wikipedia i found a non - exact location. 
They said that in the description. So i grap the wrong Wikipedia location and upload it to OpenStreetMap to correct it. 
![](/favicon/riddle5.png)

Boom, Found it : 13.19920, 77.68228

**Flag : n00bz{13.199,77.682}**

That was a consuming challenge.

# Reverse

- **description** : My friend told me they were going on vacation, but they sent me this weird PowerShell script instead of a postcard!.
```bash
$bytes = [System.Text.Encoding]::ASCII.GetBytes((cat .\flag.txt))
[System.Collections.Generic.List[byte]]$newBytes = @()
$bytes.ForEach({
    $newBytes.Add($_ -bxor 3)
    })
$newString =  [System.Text.Encoding]::ASCII.GetString($newBytes)
echo $newString | Out-File -Encoding ascii .\output.txt
```
So given this powershell script with the encrypted flag : `m33ayxeqln\sbqjp\twk\{lq~`, we need to understand the operations performed on the bytes of the flag. 
The script XORs each byte of the flag with the value 3 to create the encrypted output. Therefore, to decrypt it, we need to XOR the encrypted bytes again with the value 3.

```python
# Encrypted string
encrypted = 'm33ayxeqln\\sbqjp\\twk\\{lq~'

# Decrypt each character by XORing with 3
decrypted = ''.join(chr(ord(char) ^ 3) for char in encrypted)

print(decrypted)
```

**Flag : n00bz{from_paris_wth_xor}**


# Web

### Passwordless

- **description** : Tired of storing passwords? No worries! This super secure website is passwordless!.
Attachments :  app.py | http://24.199.110.35:40150/

The website give us :
![](/favicon/passw1.png)

The app.py : 
```python
#!/usr/bin/env python3
from flask import Flask, request, redirect, render_template, render_template_string
import subprocess
import urllib
import uuid
global leet

app = Flask(__name__)
flag = open('/flag.txt').read()
leet=uuid.UUID('13371337-1337-1337-1337-133713371337')

@app.route('/',methods=['GET','POST'])
def main():
    global username
    if request.method == 'GET':
        return render_template('index.html')
    elif request.method == 'POST':
        username = request.values['username']
        if username == 'admin123':
            return 'Stop trying to act like you are the admin!'
        uid = uuid.uuid5(leet,username) # super secure!
        return redirect(f'/{uid}')

@app.route('/<uid>')
def user_page(uid):
    if uid != str(uuid.uuid5(leet,'admin123')):
        return f'Welcome! No flag for you :('
    else:
        return flag

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=1337)
```
Simply this Flask application is set up to create a UUID based on a username and redirect the user to a URL containing the generated UUID. If the UUID corresponds to the 'admin123' user, it returns the flag.

so lets break it :
```python
import uuid

namespace_uuid = uuid.UUID('13371337-1337-1337-1337-133713371337')
username = 'admin123'

# Generate the UUID for the given username and namespace
correct_uid = uuid.uuid5(namespace_uuid, username)
print(correct_uid)
```
To generate the correct UUID that will allow access to the flag, we need to follow the process defined in the code. The UID is generated using the uuid5 function, which takes a namespace UUID and a name (username) to produce a deterministic UUID.

And we got the uid, navigate with it and get the flag : [url](http://24.199.110.35:40150/3c68e6cc-15a7-59d4-823c-e7563bbb326c)

**Flag : n00bz{1337-13371337-1337-133713371337-1337}**

# Blockchain

My TEAMmate will cover the blockchain challs sooon.








