# Introc

<figure><img src="../../../.gitbook/assets/image (4).png" alt=""><figcaption></figcaption></figure>

Given an ELF file immediately decompile using ida and got this function:

main

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  __int64 i; // rax
  char v5[40]; // [rsp+0h] [rbp-38h] BYREF
  unsigned __int64 v6; // [rsp+28h] [rbp-10h]

  v6 = __readfsqword(0x28u);
  sub_4015C0();
  if ( qword_4034A8 < 0 )
    return 1;
  __printf_chk(2, &unk_4020A0);
  if ( fgets(v5, 28, stdin) )
  {
    for ( i = 0; i != 27; ++i )
    {
      if ( (*((_BYTE *)off_4034C8 + i) ^ (unsigned __int8)v5[i]) != *((_BYTE *)off_4034B0 + i) )
      {
        puts(aUhh);
        exit(-1);
      }
    }
    puts(s);
  }
  else
  {
    puts("Error reading input.");
  }
  return 0;
}

```

In short, what it does:

* fgets(v5, 28, stdin), which means the length that the program checks is 27 byte
* Loop if A\[i] ^ v5\[i] != B\[i] => fail
* Therefore the correct input is v5\[i] = A\[i] ^ B\[i], with v5 is user input

Then in the pseudo code we can see that **off\_4034C8** points to array A, and **off\_4034B0** points to array B. So to extract the key, I used an LD=PRELOAD hook that overrides fgets, dereferences **off\_4034C8** and **off\_4034B0**, computes A ^ B , writes it into the input buffer, and prints the 27-byte result.

Hook.c:

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#define ADDR_OFF_4034B0 0x4034B0UL
#define ADDR_OFF_4034C8 0x4034C8UL

static void dump_ascii(const unsigned char *buf, int n) {
    char out[64]; int k = 0;
    for (int i = 0; i < n; i++) {
        unsigned char c = buf[i];
        out[k++] = (c >= 0x20 && c <= 0x7e) ? c : '.';
    }
    write(2, out, k);
}

static void dump_hex(const unsigned char *buf, int n) {
    static const char *hx = "0123456789abcdef";
    char out[128]; int k = 0;
    for (int i = 0; i < n; i++) {
        unsigned char c = buf[i];
        out[k++] = hx[c >> 4];
        out[k++] = hx[c & 0xF];
        if (i + 1 < n) out[k++] = ' ';
    }
    write(2, out, k);
}

char *fgets(char *s, int size, FILE *stream) {
    uintptr_t pB = *(uintptr_t*)ADDR_OFF_4034B0; // pointer runtime ke array B
    uintptr_t pA = *(uintptr_t*)ADDR_OFF_4034C8; // pointer runtime ke array A
    unsigned char *A = (unsigned char*)pA;
    unsigned char *B = (unsigned char*)pB;

    int need = 27;
    int n = (size > need + 1) ? need : (size - 1);
    if (n < 0) n = 0;

    for (int i = 0; i < n; i++) s[i] = A[i] ^ B[i];

    // === Dump ke stderr supaya kamu bisa lihat flag/input yang benar ===
    const char *hdr1 = "\n[solver] XOR result (27 bytes)\nASCII : ";
    write(2, hdr1, strlen(hdr1));
    dump_ascii((unsigned char*)s, n);
    const char *hdr2 = "\nHEX   : ";
    write(2, hdr2, strlen(hdr2));
    dump_hex((unsigned char*)s, n);
    const char *hdr3 = "\nRAW\\x: ";
    write(2, hdr3, strlen(hdr3));
    // \x-escaped
    char esc[27*4+1]; int k=0;
    for (int i=0;i<n;i++) {
        unsigned char c = s[i];
        esc[k++]='\\'; esc[k++]='x';
        static const char *hx = "0123456789abcdef";
        esc[k++]=hx[c>>4]; esc[k++]=hx[c&0xF];
    }
    write(2, esc, k);
    write(2, "\n\n", 2);
    // ===================================================================

    if (n < size) { s[n] = '\n'; if (n + 1 < size) s[n + 1] = '\0'; }
    return s;
}
```

When we run it, we get the flag:

<figure><img src="../../../.gitbook/assets/image (5).png" alt=""><figcaption></figcaption></figure>

#### Flag: WRECKIT60{i'm\_sooo\_1ntr0vert\_;(;(;(;(}
