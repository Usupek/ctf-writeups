# Dunno

<figure><img src="../../../.gitbook/assets/image (2) (1).png" alt=""><figcaption></figcaption></figure>

Given an ELF file and story.md.enc. Immediately decompile using ida. And got these functions:

main

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  FILE *v4; // rbp
  __int64 v5; // r14
  _DWORD *v6; // rbx
  size_t v7; // rax
  unsigned int v8; // edx
  char *v9; // rax
  unsigned int v10; // esi
  unsigned int v11; // edx
  __int64 v12; // rcx
  unsigned int v13; // edi
  unsigned __int64 v14; // rdi
  FILE *s; // [rsp+10h] [rbp-68h]
  __int64 n; // [rsp+18h] [rbp-60h]
  __int64 v18; // [rsp+28h] [rbp-50h] BYREF
  unsigned int ptr; // [rsp+34h] [rbp-44h] BYREF
  unsigned __int64 v20; // [rsp+38h] [rbp-40h]

  v20 = __readfsqword(0x28u);
  if ( a1 != 3 )
  {
    __fprintf_chk(stderr, 2, "Usage: %s <input_file> <output_binary_file>\n", *a2);
    return 1;
  }
  v4 = fopen(a2[1], "rb");
  if ( !v4 )
  {
    perror("Error opening input file");
    return 1;
  }
  s = fopen(a2[2], "wb");
  if ( !s )
  {
    perror("Error opening output file");
    fclose(v4);
    return 1;
  }
  v5 = 0;
  fseek(v4, 0, 2);
  v18 = ftell(v4);
  fseek(v4, 0, 0);
  n = (v18 + 3) / 4;
  v6 = malloc(4 * n);
  if ( !v6 )
  {
    fwrite("Failed to allocate memory\n", 1u, 0x1Au, stderr);
    fclose(v4);
    fclose(s);
    return 1;
  }
  while ( 1 )
  {
    v7 = fread(&ptr, 1u, 4u, v4);
    if ( !v7 )
      break;
    if ( v7 <= 3 )
    {
      v8 = 4 - v7;
      v9 = (char *)&ptr + v7;
      v10 = v8;
      if ( v8 )
      {
        v11 = 0;
        do
        {
          v12 = v11++;
          v9[v12] = 0;
        }
        while ( v11 < v10 );
      }
    }
    v13 = _byteswap_ulong(ptr);
    if ( v5 )
      v13 = sub_15D0(v13, v6[v5 - 1]);
    v14 = 3019108683LL * v13
        - 4170859393u * ((3019108683u * (unsigned __int64)v13 * (unsigned __int128)0x1079E1614uLL) >> 64);
    if ( v14 > 0xF89A4380 )
    {
      if ( (int)(((unsigned __int64)(v14
                                   - 4170859393u
                                   - (((v14 - 4170859393u) * (unsigned __int128)0x79E161422870E03uLL) >> 64)) >> 1)
               + (((v14 - 4170859393u) * (unsigned __int128)0x79E161422870E03uLL) >> 64)) < 0
        || (v14 -= 4170859393LL, v14 > 0xF89A4380) )
      {
        do
          v14 -= 0x1F1348702LL;
        while ( v14 > 0xF89A4380 );
      }
    }
    v6[v5++] = v14;
  }
  fwrite(v6, 4u, n, s);
  fwrite(&v18, 8u, 1u, s);
  fclose(v4);
  fclose(s);
  free(v6);
  __printf_chk(2, "Packing complete. Output written to '%s'\n", a2[2]);
  return 0;
}

```

sub\_15DO

```c
__int64 __fastcall sub_15D0(int a1, unsigned int a2)
{
  unsigned int v2; // edx
  unsigned int v3; // edi
  unsigned int v4; // r8d
  unsigned int v5; // esi

  v2 = ((unsigned __int16)a2 ^ (unsigned __int16)(a2 >> 12)) & 0xFFF ^ HIBYTE(a2);
  v3 = __ROR4__(a1, v2);
  v4 = v2 >> 9;
  LOBYTE(v2) = (v2 >> 5) & 0xF;
  v5 = ((v3 << (16 - v2)) ^ (v3 >> v2)) & (65537 * ((int)(unsigned __int16)(0xFFFF << v2) >> v2)) ^ (v3 << (16 - v2));
  return ((v5 << (8 - v4)) ^ (v5 >> v4)) & (16843009 * ((int)(unsigned __int8)(255 << v4) >> v4)) ^ (v5 << (8 - v4));
}

```

From these two functions we get that the ELF packs an input file into an encrypted output:

1. Read 4 bytes at a time from the input. If the last chunk is short, pad with zeros.
2. Byte-swap the 4-byte word
3. For every block after the first, run a bit-twiddling function (sub\_15D0) that depends on the previous ciphertext block.
4. compute:\
   Y = (MUL \* x) mod MOD\
   With: MOD = 0xF89A4381, MUL = 3019108683
5. Write all y\[i] to the output, then append 8 bytes holding the original file size.

using this info, we can just reverse the process to decrypt the .enc file

solver.py:

```python
import struct, sys

MOD = 0xF89A4381
MUL = 3019108683
INV_MUL = 3010430832  # MUL^{-1} mod MOD

def ror32(x, r): r &= 31; x &= 0xFFFFFFFF; return ((x >> r) | ((x << (32 - r)) & 0xFFFFFFFF)) & 0xFFFFFFFF
def rol32(x, r): r &= 31; x &= 0xFFFFFFFF; return ((x << r) | (x >> (32 - r))) & 0xFFFFFFFF

def rol16_each(x, r):
    r &= 15; x &= 0xFFFFFFFF
    lo = x & 0xFFFF; hi = (x >> 16) & 0xFFFF
    if r: lo = ((lo << r) & 0xFFFF) | (lo >> (16 - r)); hi = ((hi << r) & 0xFFFF) | (hi >> (16 - r))
    return ((hi & 0xFFFF) << 16) | (lo & 0xFFFF)

def rol8_each(x, r):
    r &= 7; res = 0
    for i in range(4):
        b = (x >> (8*i)) & 0xFF
        if r: b = ((b << r) & 0xFF) | (b >> (8 - r))
        res |= b << (8*i)
    return res & 0xFFFFFFFF

def sub_15D0_inv(z, prev):
    r = (((prev & 0xFFFF) ^ ((prev >> 12) & 0xFFFF)) & 0x0FFF) ^ ((prev >> 24) & 0xFF)
    s = (r >> 9) & 0x7
    t = (r >> 5) & 0xF
    v5 = rol8_each(z, s)
    v3 = rol16_each(v5, t)
    a1 = rol32(v3, r)
    return a1 & 0xFFFFFFFF

def bswap32(x):
    return ((x & 0xFF) << 24) | ((x >> 8 & 0xFF) << 16) | ((x >> 16 & 0xFF) << 8) | ((x >> 24) & 0xFF)

def decode(inp, outp):
    data = open(inp, "rb").read()
    orig_size = int.from_bytes(data[-8:], "little")
    body = data[:-8]
    y = [int.from_bytes(body[i:i+4], "little") for i in range(0, len(body), 4)]

    out = bytearray()
    for i, yi in enumerate(y):
        xi = (yi * INV_MUL) % MOD
        w_be = xi if i == 0 else sub_15D0_inv(xi, y[i-1])
        out += bswap32(w_be).to_bytes(4, "little")

    open(outp, "wb").write(out[:orig_size])

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} story.md.enc story.md"); sys.exit(1)
    decode(sys.argv[1], sys.argv[2]); print("OK -> decoded to", sys.argv[2])

```

when we run it, we get the flag:

<figure><img src="../../../.gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

#### Flag: WRECKIT60{5cfd0862dd83b00c76b4a568eb67064b614b752e14121b62dbfac62257b1ba23}
