---
description: golang reverse engineering challenge
---

# baby-goes-re

<figure><img src="../../../../.gitbook/assets/image (23).png" alt=""><figcaption></figcaption></figure>

given a golang binary file. Then we proceed to disassamble it using binja.

<figure><img src="../../../../.gitbook/assets/image (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

this is the main function. As we can see here there's a call to main. Checkflag function, so we take a look

<figure><img src="../../../../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../.gitbook/assets/image (4) (1) (1).png" alt=""><figcaption></figcaption></figure>

in short this function does:

1. Compares the user's flag byte-by-byte with encrypted bytes from a hardcoded string
2. Calculates the offset for each byte using **offset = r8 + rsi + 0x1337**, where **r8** and **rsi** increase non-linearly, causing the flag bytes to be **scattered far apart** in the buffer
3. Each byte (as integer) is converted to a string using **intstring()** before comparison
4. If any comparison fails, it immediately calls **main.fail()** and exits

so we then proceed to extract the hardcoded string. We see in the **main.main()** function the string header is **"g9EPa:K5\_C:BK\[Dr\*Z-).\*y}Qn}\_EA}O",** however this is not the full string. So we just use strings on the ELF file in the terminal then dump it in **encoded\_dump.bin**.

Solver:

```python
flag_length = 53  # length of the flag

# Encrypted memory dump as a string
encoded_file = "encoded_dump.bin"

# Read all bytes from the file
with open(encoded_file, "rb") as f:
    encoded_bytes = f.read()

r8 = 0
rsi = 0

result_bytes = []

for i in range(flag_length):
    offset = r8 + rsi + 0x1337
    if offset >= len(encoded_bytes):
        print(f"Error: offset {offset} exceeds encoded_bytes length ({len(encoded_bytes)})")
        break
    result_bytes.append(encoded_bytes[offset])
    next_rsi = r8 + rsi + 0x1338
    r8 += 0x33
    rsi = next_rsi

flag = bytes(result_bytes).decode('ascii', errors='replace')
print("Decrypted flag:", flag)
```

#### Flag: justCTF{W3lc0m3\_t0\_R3v1NG!\_Th4t\_w45nt-s0-B4d-w45\_1t?}
