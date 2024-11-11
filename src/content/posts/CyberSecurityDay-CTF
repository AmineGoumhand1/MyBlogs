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

**solution** : Also in this challenge, a variant of vigenere cipher on the show here, it is Beaufort cipher. So the first thing to do is to apply a kasiski test to know the length of key ( 5 ) and brute force the 2 first characters ( because of the palindrome utility ) and also the forth character and search for INSEC in each iteration.

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

## decentral
**description** : 

**given files** :

**solution** : 

## Scrambled
**description** : 

**given files** :

**solution** : 

## Encoded
**description** : 

**given files** :

**solution** : 




# Forensics
## QQR
**description** : 

**given files** :

**solution** : 

## Broken-Satellite
**description** : 

**given files** :

**solution** : 

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
**description** : 

**given files** :

**solution** : 

## Suspect-Net-008
**description** : 

**given files** :

**solution** : 

## Resolution
**description** : 

**given files** :

**solution** : 

# Reverse Enginnering
## e_asm
**description** : 

**given files** :

**solution** : 

## MajoorCost
**description** : 

**given files** :

**solution** : 


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

**solution** : Also in this challenge, a variant of vigenere cipher on the show here, it is Beaufort cipher. So the first thing to do is to apply a kasiski test to know the length of key ( 5 ) and brute force the 2 first characters ( because of the palindrome utility ) and also the forth character and search for INSEC in each iteration.

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

## decentral
**description** : 

**given files** :

**solution** : 

## Scrambled
**description** : 

**given files** :

**solution** : 

## Encoded
**description** : 

**given files** :

**solution** : 




# Forensics
## QQR
**description** : 

**given files** :

**solution** : 

## Broken-Satellite
**description** : 

**given files** :

**solution** : 

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
**description** : 

**given files** :

**solution** : 

## Suspect-Net-008
**description** : 

**given files** :

**solution** : 

## Resolution
**description** : 

**given files** :

**solution** : 

# Reverse Enginnering
## e_asm
**description** : 

**given files** :

**solution** : 

## MajoorCost
**description** : 

**given files** :

**solution** : 
