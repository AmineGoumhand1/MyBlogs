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
I am also happy to be a part of this as the author of the challenges except the WEB category.

The CTF contains several categories like Crypto, Steganography, Forensics, Reverse Engineering, Misc, Web and Osint.
You can find files in my github repo. 


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
![gg]('Capture d’écran 2024-11-11 173952.png')


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
            # Find positions in the alphabet (A=0, B=1, ..., Z=25)
            key_char = key[key_index % key_length]
            key_pos = alphabet.index(key_char)
            cipher_pos = alphabet.index(char)

            # Perform Beaufort decryption (Key - Ciphertext) mod 26
            decrypted_pos = (key_pos - cipher_pos) % 26
            decrypted_message += alphabet[decrypted_pos]

            # Move to the next letter in the key
            key_index += 1
        else:
            # If it's not in the alphabet, add it unchanged
            decrypted_message += char

    return decrypted_message

# Example usage:
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


# Scrambled
**description** : It's clearly not a scrambled file, but my machine tells me the opposite. 

**given files** : bruh

**solution** : This challenge is a text-steganography based challenge, searching a bit on text steganography you can find that we can hide informations in spaces using the Zero width technique. ( another way to do that is to inspect it in vim or a hex editor ). For us let's use this web to reveil hidden data.

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




## Broken-Satellite
**description** : Our satellites not doing great up there.

**given files** : satellitecomm.wav

**solution** : This transmission wav is called sstv transmission used for example by NASA to transmit images from space to earth. so as a classic challenge, you should decode it and get the flag using qsstv tool, but the transmission audio containing the image of the flag is merged with a fake flag audio, so the solution is to split the audio to two channels and then decode them to recover the flag.

You can use ffmpeg to split the audio channels, `ffmpeg -i satellitecomm.wav -ac 1 -map_channel 0.0.0 output_left.wav` 
`ffmpeg -i satellitecomm.wav -ac 1 -map_channel 0.0.1 output_right.wav`.


## freepalestine
**description** : 

**given files** :

**solution** : 




# Osint
## MyCastle-1
**description** : 

**given files** :

**solution** : 

## MyCastle-2
**description** : 

**given files** :

**solution** : 

## MyCastle-2
**description** : 

**given files** :

**solution** : 

## MyCastle-3
**description** : 

**given files** :

**solution** : 

# Misc
## Suspect-Net-007
**description** : Have you heard about exfiltration?

**given files** : netw.pcapng

**solution** : In this networking challenge, you are given a pcapng traffic file to exfiltrate. Investigating a little bit in it, you can find weird ICMP packets used to test communication so analysing these packets you can conclude that the first ICMP packet contains 2 bytes of base64 after it is followed by 9 fake packets and so on. Note that the time difference will help you to do that.

so reassemble the base64 bytes will give us SU5TRUN7cDFuOV9wMW45X2QxZF95b3VfbDFrM18zeGYxbDdyNDcxMG59 base64 

## Suspect-Net-008
**description** : Alert! Our SOC team managed to detect some malicious activities on our network. Can you help them figure out what is about?

**given files** : netw.pcapng

**solution** : This challenge also contain ICMP packets exfiltration, This time you should analyse the TTL section of each packet and you'll see something unusuall, TTL contains the ascii code ord of each byte of the flag, so reassemble them give us the flag.


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
**description** : 

**given files** : 

**solution** : 


## MajoorCost
**description** : 

**given files** :

**solution** : 
