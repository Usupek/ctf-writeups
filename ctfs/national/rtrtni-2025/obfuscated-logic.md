# Obfuscated Logic

<figure><img src="../../../.gitbook/assets/unknown (4).png" alt=""><figcaption></figcaption></figure>

Given an ELF file, we can see from the challenge description that we have to do **dynamic analysis**. But before that, we do **static analysis** first to see the program's algorithm to encrypt/decrypt the flag.

check\_password:

```c
__int64 __fastcall check_password(const char *a1)
{
  unsigned __int8 v2; // [rsp+1Fh] [rbp-11h] BYREF
  int v3; // [rsp+20h] [rbp-10h] BYREF
  int i; // [rsp+24h] [rbp-Ch]
  unsigned __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  if ( strlen(a1) != 40 )
    return 0;
  v3 = 0;
  for ( i = 0; i < 40; ++i )
  {
    v2 = a1[i];
    if ( !(unsigned __int8)transform_char(&v2, i) )
      return 0;
    junk_operations(&v3);
    if ( !validate_char(v2, i) )
      return 0;
  }
  return 1;
}
```

transform\_char:

```c
__int64 __fastcall transform_char(_BYTE *a1, char a2)
{
  *a1 += a2;
  return 1;
}
```

junk\_operations:

```c
__int64 __fastcall junk_operations(_DWORD *a1)
{
  __int64 result; // rax

  *a1 = 5 * *a1 + 3;
  result = (unsigned int)(*a1 % 100);
  *a1 = result;
  return result;
}
```

validate\_char:

```c
_BOOL8 __fastcall validate_char(unsigned __int8 a1, int a2)
{
  return (a1 ^ key[a2 % 4]) == encoded_flag[a2];
}
```

from these functions we get the check flag algorithm:

```python
encoded_flag[i] = ((input[i] + i) & 0xff) ^ key[i % 4]
```

then we proceed to analyze using gdb:

<figure><img src="../../../.gitbook/assets/unknown (1) (1).png" alt=""><figcaption></figcaption></figure>

from here we found some interesting functions, check\_password and validate\_char. But we can't set breakpoint cause PIE is on. so we use **start** command to put a temporary breakpoint on main.

<figure><img src="../../../.gitbook/assets/unknown (2) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/unknown (3) (1).png" alt=""><figcaption></figcaption></figure>

after we hit the breakpoint, now we can put breakpoints on check\_password and validate\_char

<figure><img src="../../../.gitbook/assets/unknown (4) (1).png" alt=""><figcaption></figcaption></figure>

then we continue until we hit **validate\_char**

<figure><img src="../../../.gitbook/assets/unknown (5).png" alt=""><figcaption></figcaption></figure>

after we stop on **validate\_char**, we see the RIP-relative disassembly

<figure><img src="../../../.gitbook/assets/unknown (6).png" alt=""><figcaption></figcaption></figure>

here, we got the key address and the **encoded\_flag**. Then we just dump the key and the encoded flag

<figure><img src="../../../.gitbook/assets/unknown (7).png" alt=""><figcaption></figcaption></figure>

solver.py:

```python
key = [0x13, 0x37, 0x42, 0x69]
encoded_flag = [
    0x41, 0x62, 0x16, 0x3e, 0x41, 0x79, 0x7a, 0x55, 0x90, 0x7a,
    0x2d, 0x13, 0x7d, 0x44, 0xc1, 0xeb, 0x60, 0x45, 0xc4, 0x15,
    0x90, 0xb4, 0x37, 0x09, 0x98, 0x4f, 0x25, 0xfd, 0x68, 0x47,
    0xd1, 0xe6, 0x96, 0xa4, 0xd0, 0xfb, 0x88, 0xbd, 0xda, 0xcd,
]

def decode(enc, key):
    out = []
    for i in range(len(enc)):
        v = (enc[i] ^ key[i % 4]) - i
        out.append(v & 0xff)
    return bytes(out)

if __name__ == "__main__":
    flag = decode(encoded_flag, key)
    print("Decoded:", flag.decode(errors="replace"))
```

if we run it, we get the flag:

<figure><img src="../../../.gitbook/assets/unknown (8).png" alt=""><figcaption></figcaption></figure>

#### Flag: RTRTNI25{Deobfuscation\_Is\_My\_Superpower}
