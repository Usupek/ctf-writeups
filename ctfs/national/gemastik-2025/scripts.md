---
description: Reverse Engineering
---

# Scripts

<figure><img src="../../../.gitbook/assets/unknown (17).png" alt=""><figcaption></figcaption></figure>

Given an ELF file, if we run it:

<figure><img src="../../../.gitbook/assets/unknown (18).png" alt=""><figcaption></figcaption></figure>

as we can see, the program asked for the flag and if we input a wrong flag, then the program gives a "WRONG" output. Then we proceed to analyze using GDB with a python script to help with breakpoints.

gdb.py:

```python
from pwn import *

binary = "./main"
elf = context.binary = ELF(binary, checksec=False)
context.terminal = 'kitty'

# Alamat buffer (dari IDA)
ADDR_FLAGBUF = 0x54CC00
ADDR_BLOB1   = 0x54CBA0
ADDR_BLOB2   = 0x54CBC0
ADDR_BLOB3   = 0x54CBE0

p = process(binary)

gdb.attach(p, gdbscript=f"""
   b *0x401C7C          # breakpoint sebelum loop cek input
   c
""")

p.interactive()
```

when we run the script, the program will break before input and attach to gdb. inside GDB, we run

`dump memory dump_flagbuf.bin 0x54CC00 0x54CC00+0x500`

then we get **dump\_flagbuf.bin**:

<figure><img src="../../../.gitbook/assets/unknown (19).png" alt=""><figcaption></figcaption></figure>

from here we got the op codes, ct array, and k array. now we just have to find out what the op codes do. We proceed to analyze using GDB:

<figure><img src="../../../.gitbook/assets/unknown (20).png" alt=""><figcaption></figcaption></figure>

Using GDB, I noticed the program looping from **0x407f9f** to **0x407fb0**. In this section, the program loads an address into **r9** and then jumps to it. This identifies it as the VM Dispatch, where each iteration fetches a new handler from a table and executes it.

So the idea is to hook execution at the dispatch point, allowing us to log the handler functions executed for each byte of our input.

tracevm script:

```python
import gdb, os

bp_addr = 0x407fa3
bp = None
logfile = open("vm_trace.log", "w")
seen = {}

os.makedirs("handlers", exist_ok=True)

def classify_and_dump(addr: int) -> str:
   """Disassemble handler, save to file, return guessed mnemonic."""
   try:
       output = gdb.execute(f"disassemble {hex(addr)},+64", to_string=True)  # dump more bytes
       # save to file
       fname = f"handlers/{hex(addr)}.asm"
       with open(fname, "w") as f:
           f.write(output)

       lower = output.lower()
       if "add" in lower:
           return "ADD"
       if "xor" in lower:
           return "XOR"
       if "imul" in lower or "mul" in lower:
           return "MUL"
       if "sub" in lower:
           return "SUB"
       return "OTHER"
   except Exception as e:
       return f"??? ({e})"

def stop_handler(event):
   try:
       rip = int(gdb.parse_and_eval("$rip"))
       if rip == bp_addr:
           r9 = int(gdb.parse_and_eval("$r9"))
           if r9 not in seen:
               mnemonic = classify_and_dump(r9)
               seen[r9] = mnemonic
           else:
               mnemonic = seen[r9]

           line = f"{hex(r9)} {mnemonic}"
           gdb.write(f"[VM DISPATCH] {line}\n")
           logfile.write(line + "\n")
           logfile.flush()

           gdb.execute("c")
   except Exception as e:
       gdb.write(f"[stop_handler error] {e}\n")

class TraceVM(gdb.Command):
   def __init__(self):
       super(TraceVM, self).__init__("tracevm", gdb.COMMAND_USER)

   def invoke(self, arg, from_tty):
       global bp
       if bp:
           bp.delete()
       bp = gdb.Breakpoint("*" + hex(bp_addr), internal=False)
       gdb.events.stop.connect(stop_handler)
       gdb.write(f"[+] Breakpoint set at {hex(bp_addr)}, tracing enabled\n")

TraceVM()
```

Basically, the script sets a breakpoint at **0x407fa3**. Every time this breakpoint is hit, it reads the **r9** register, disassembles a few bytes, and classifies the handler (XOR, ADD, SUB, etc.) by inspecting the disassembly. Finally, it logs the address and classification result to **vm\_trace.log** and continues execution.



when we run the script, we get these:

<figure><img src="../../../.gitbook/assets/unknown (21).png" alt=""><figcaption></figcaption></figure>

vm\_trace.log:

<figure><img src="../../../.gitbook/assets/unknown (22).png" alt=""><figcaption></figcaption></figure>

and full disassambly of the handler is stored in handlers/\*asm:

<figure><img src="../../../.gitbook/assets/unknown (23).png" alt=""><figcaption></figcaption></figure>

from that, we got these:

* J3s5l -> XOR
* M9kp2 -> ADD
* Qwx7z -> SUB

then with the ct array, keys, and op codes, we can make a script to reconstruct the flag:

```python
ops = ["j3s5l","j3s5l","m9kp2","qwx7z","qwx7z","m9kp2","j3s5l","j3s5l",
      "qwx7z","j3s5l","j3s5l","qwx7z","m9kp2","j3s5l","qwx7z","j3s5l",
      "m9kp2","j3s5l","j3s5l","m9kp2","m9kp2","qwx7z","j3s5l","m9kp2",
      "j3s5l","m9kp2","m9kp2","j3s5l","m9kp2","qwx7z","qwx7z","qwx7z","qwx7z"]

keys = [143,193,38,93,97,13,149,22,102,163,38,84,55,157,130,12,65,133,194,3,9,162,198,41,77,20,55,76,17,192,207,104,163]

ct   = [200,132,39,158,180,71,220,93,151,155,93,185,67,194,245,111,49,236,178,113,96,272,161,54,33,77,55,43,100,289,310,205,288]

def j3s5l(x,k): return x ^ k
def m9kp2(x,k): return (x - k) & 0xff   # flipped
def qwx7z(x,k): return (x + k) & 0xff   # flipped
opfunc = {"j3s5l": j3s5l, "m9kp2": m9kp2, "qwx7z": qwx7z}

flag = []
for i,(op,k,target) in enumerate(zip(ops, keys, ct)):
   cands = []
   for ch in range(0x20,0x7f):
       res = opfunc[op](ch, k)
       if res == target or res == (target & 0xff):
           cands.append(chr(ch))
   flag.append((cands or ["?"])[0])

print("Recovered flag:", "".join(flag))
```

is we run it, we get the flag:

<figure><img src="../../../.gitbook/assets/unknown (24).png" alt=""><figcaption></figcaption></figure>

#### Flag: GEMASTIK18{ez\_scripting\_language}
