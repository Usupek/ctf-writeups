---
description: C++ Constructor reverse enginnering
---

# Constructor

<figure><img src="../../.gitbook/assets/image (5).png" alt=""><figcaption></figcaption></figure>

This is a reverse engineering challenge. Given a tar file and after we extract it we got an ELF file.

<figure><img src="../../.gitbook/assets/image (2) (1).png" alt=""><figcaption></figcaption></figure>

when we run the ELF file it seems like it doesnt do much, it just prints out this eyes emoji. Then we proceed to dissasamble it using ghidra.

<figure><img src="../../.gitbook/assets/image (4) (1).png" alt=""><figcaption></figcaption></figure>

from the info we gathered before we know the ELF is stripped. As we can see the \_start function doesn't do much, cause the program is coded in C++ constructor. this video explains constructor very well [https://youtu.be/FZK7BZhST9g?si=sL2HgASgf3QaZ4vT](https://youtu.be/FZK7BZhST9g?si=sL2HgASgf3QaZ4vT) .

So, we proceed to search for the function that have the actual code. We found this function

<figure><img src="../../.gitbook/assets/image (5) (1).png" alt=""><figcaption></figcaption></figure>

it has the string "Correct!" in it and the decryption algorithm is in the do while loop.

what the do while loop does:

1. Read encrypted byte from address 0x403040
2. XOR with incrementing value 'bVar6', starting from an unknown seed
3. XOR the result with (i >> 1)
4. XOR with constant 0x5a
5. loop until 0x2a which is 42

then we extract the 42 encrypted bytes directly from the binary:

<figure><img src="../../.gitbook/assets/image (6).png" alt=""><figcaption></figcaption></figure>

then decrypt using python

```python
cipher_bytes = bytes.fromhex(
    "33 21 00 6d 5f ab 86 b4 d4 2d 36 3a 4e 90 8c e3"
    "cc 2e 09 6c 49 b8 8f f7 cc 22 4e 4d 5e b8 80 cb"
    "d3 da 20 29 70 02 b7 d1 b7 c4".replace(" ", "")
)

assert len(cipher_bytes) == 42

bVar6 = 0
plaintext = bytearray()

for i in range(42):
    temp = cipher_bytes[i] ^ ((i >> 1) & 0xFF) ^ 0x5a
    original = temp ^ (bVar6 & 0xFF)
    plaintext.append(original)
    bVar6 = (bVar6 + 0x1f) & 0xFF  # Ensure byte overflow like in C

print("Recovered plaintext:")
print(plaintext.decode(errors='replace'))  # replace errors if any non-printable

```

#### Flag: i**dek{he4rd\_0f\_constructors?\_now\_you\_d1d!!}**

