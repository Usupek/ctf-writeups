---
description: Reverse Engineering
---

# HarderBetterFasterStronger

<figure><img src="../../../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

Given an ELF file also an output.txt file which contains a ciphertext. Then we proceed to decompile the ELF file and got this function:

Main:

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  _BYTE *v3; // rbx
  __int64 *v4; // rdi
  __int64 i; // rcx
  __int64 v6; // r8
  __int64 v7; // r13
  unsigned __int64 v8; // r14
  _BYTE *v9; // rax
  _BYTE *v10; // rbp
  char *v11; // r15
  __int64 v12; // rcx
  unsigned __int64 v13; // rdx
  char v14; // al
  unsigned __int64 v15; // rcx
  __int64 v16; // r8
  char v17; // bl
  unsigned __int64 v18; // r13
  unsigned __int64 v19; // rcx
  unsigned __int64 v20; // r10
  char v21; // r11
  _QWORD *v22; // rdx
  char v23; // r10
  _QWORD *v24; // rdx
  unsigned __int64 v25; // rbx
  __int64 v26; // rax
  __int64 v27; // rcx
  __int64 v28; // r8
  __int64 v29; // r9
  size_t v31; // r14
  __int64 v32; // rax
  _QWORD *v33; // r15
  char *v34; // rax
  char v35; // si
  unsigned __int64 v36; // rax
  __int64 v37; // r14
  _BYTE *v38; // rbp
  char v39; // al
  __int64 v40; // rsi
  __int64 v41; // rax
  __int64 v42; // rdx
  int v43; // eax
  char v44; // si
  unsigned __int64 v45; // rax
  _BYTE *v46; // rax
  _QWORD *v47; // rdi
  void *v48; // rbp
  int v49; // eax
  __int64 v50; // [rsp+0h] [rbp-2F8h]
  char v51; // [rsp+0h] [rbp-2F8h]
  char v52; // [rsp+0h] [rbp-2F8h]
  unsigned __int64 v53; // [rsp+8h] [rbp-2F0h]
  _QWORD v54[4]; // [rsp+10h] [rbp-2E8h] BYREF
  __int64 v55; // [rsp+30h] [rbp-2C8h] BYREF
  __int64 v56; // [rsp+38h] [rbp-2C0h]
  __int64 v57; // [rsp+40h] [rbp-2B8h]
  unsigned __int64 v58; // [rsp+50h] [rbp-2A8h] BYREF
  _BYTE *v59; // [rsp+58h] [rbp-2A0h]
  _BYTE *v60; // [rsp+60h] [rbp-298h]
  _QWORD v61[2]; // [rsp+70h] [rbp-288h] BYREF
  char v62[16]; // [rsp+80h] [rbp-278h] BYREF
  void *src; // [rsp+90h] [rbp-268h] BYREF
  unsigned __int64 v64; // [rsp+98h] [rbp-260h]
  _QWORD v65[2]; // [rsp+A0h] [rbp-258h] BYREF
  _QWORD *v66; // [rsp+B0h] [rbp-248h] BYREF
  unsigned __int64 v67; // [rsp+B8h] [rbp-240h]
  _QWORD v68[34]; // [rsp+C0h] [rbp-238h] BYREF
  char v69; // [rsp+1D0h] [rbp-128h]
  unsigned __int64 v70; // [rsp+2B8h] [rbp-40h]

  v70 = __readfsqword(0x28u);
  std::ios_base::sync_with_stdio(0, (bool)a2);
  qword_4248 = 0;
  v3 = (_BYTE *)operator new(1u);
  v54[0] = v3;
  *v3 = 37;
  v54[2] = v3 + 1;
  v54[1] = v3 + 1;
  v61[0] = v62;
  strcpy(v62, "flag.txt");
  v61[1] = 8;
  std::ifstream::basic_ifstream(&v66, v61, 4);
  if ( (v69 & 5) != 0 )
  {
    v4 = &v55;
    for ( i = 6; i; --i )
    {
      *(_DWORD *)v4 = 0;
      v4 = (__int64 *)((char *)v4 + 4);
    }
    goto LABEL_5;
  }
  v31 = 0;
  v32 = *(v66 - 3);
  v58 = 15;
  v33 = *(_QWORD **)((char *)&v68[27] + v32);
  src = v65;
  while ( v33 )
  {
    v34 = (char *)v33[2];
    if ( (unsigned __int64)v34 < v33[3] )
    {
      if ( v31 >= v58 )
        goto LABEL_52;
LABEL_26:
      v35 = *v34;
      goto LABEL_27;
    }
    if ( (*(unsigned int (__fastcall **)(_QWORD *))(*v33 + 72LL))(v33) == -1 )
      break;
    v34 = (char *)v33[2];
    if ( v58 <= v31 )
    {
LABEL_52:
      while ( (unsigned __int64)v34 >= v33[3] )
      {
        if ( (*(unsigned int (__fastcall **)(_QWORD *))(*v33 + 72LL))(v33) == -1 )
          goto LABEL_31;
        if ( v58 == v31 )
          goto LABEL_59;
LABEL_65:
        v34 = (char *)v33[2];
        if ( (unsigned __int64)v34 < v33[3] )
        {
LABEL_54:
          v44 = *v34;
          goto LABEL_55;
        }
        v49 = (*(__int64 (__fastcall **)(_QWORD *))(*v33 + 72LL))(v33);
        v44 = v49;
        if ( v49 == -1 )
          goto LABEL_69;
LABEL_55:
        *((_BYTE *)src + v31) = v44;
        v45 = v33[2];
        if ( v45 < v33[3] )
          v33[2] = v45 + 1;
        else
          (*(void (__fastcall **)(_QWORD *))(*v33 + 80LL))(v33);
        v34 = (char *)v33[2];
        ++v31;
      }
      if ( v31 != v58 )
        goto LABEL_54;
LABEL_59:
      v58 = v31 + 1;
      v46 = (_BYTE *)std::string::_M_create();
      v47 = src;
      v48 = v46;
      if ( v31 == 1 )
      {
        *v46 = *(_BYTE *)src;
        v47 = src;
      }
      else if ( v31 )
      {
        memcpy(v46, src, v31);
        v47 = src;
      }
      if ( v47 != v65 )
        operator delete(v47, v65[0] + 1LL);
      src = v48;
      v65[0] = v58;
      goto LABEL_65;
    }
    if ( (unsigned __int64)v34 < v33[3] )
      goto LABEL_26;
    v43 = (*(__int64 (__fastcall **)(_QWORD *))(*v33 + 72LL))(v33);
    v35 = v43;
    if ( v43 == -1 )
    {
LABEL_69:
      *((_BYTE *)src + v31) = -1;
      BUG();
    }
LABEL_27:
    *((_BYTE *)src + v31) = v35;
    v36 = v33[2];
    if ( v36 >= v33[3] )
      (*(void (__fastcall **)(_QWORD *))(*v33 + 80LL))(v33);
    else
      v33[2] = v36 + 1;
    ++v31;
  }
LABEL_31:
  v64 = v31;
  *((_BYTE *)src + v31) = 0;
  v37 = v64;
  if ( v64 )
  {
    while ( 1 )
    {
      v38 = src;
      v39 = *((char *)src + v37 - 1);
      if ( v39 != 10 && v39 != 13 )
        break;
      std::string::_M_erase(&src, v37 - 1, 1);
      v37 = v64;
      if ( !v64 )
        goto LABEL_35;
    }
    v55 = 0;
    v56 = 0;
    v57 = 0;
    if ( v37 < 0 )
LABEL_48:
      std::__throw_length_error("cannot create std::vector larger than max_size()");
    v41 = operator new(v37);
    v42 = 0;
    v40 = v41 + v37;
    v55 = v41;
    v57 = v41 + v37;
    do
    {
      *(_BYTE *)(v41 + v42) = v38[v42];
      ++v42;
    }
    while ( v37 != v42 );
  }
  else
  {
LABEL_35:
    v55 = 0;
    v40 = 0;
    v57 = 0;
  }
  v56 = v40;
  std::string::_M_dispose(&src);
LABEL_5:
  std::ifstream::~ifstream(&v66);
  std::string::_M_dispose(v61);
  v6 = v56;
  v7 = v55;
  v8 = v56 - v55;
  if ( v56 - v55 < 0 )
    goto LABEL_48;
  v59 = 0;
  v60 = 0;
  if ( v56 == v55 )
  {
    v58 = 0;
    v10 = 0;
    v60 = 0;
  }
  else
  {
    v50 = v56;
    v9 = (_BYTE *)operator new(v56 - v55);
    v6 = v50;
    v58 = (unsigned __int64)v9;
    v10 = v9 + 1;
    v60 = &v9[v8];
    *v9 = 0;
    if ( v8 != 1 )
    {
      v10 = &v9[v8];
      memset(v9 + 1, 0, v8 - 1);
      v6 = v50;
    }
  }
  v59 = v10;
  v11 = (char *)v58;
  v12 = 0;
  v13 = 0;
  if ( v6 != v7 )
  {
    do
    {
      v14 = v12 ^ __ROL1__(3 * *v3 + 5, 2);
      v12 = (unsigned int)(v12 + 13);
      v11[v13] = *(_BYTE *)(v7 + v13) ^ (v14 - (v13 & 0xF)) ^ 6;
      ++v13;
    }
    while ( v8 > v13 );
  }
  v67 = 0;
  v66 = v68;
  LOBYTE(v68[0]) = 0;
  std::string::reserve(&v66, 2 * (v10 - v11), v13, v12);
  for ( ; v10 != v11; *((_BYTE *)v66 + v25 + 1) = 0 )
  {
    v17 = *v11;
    v18 = v67;
    v19 = 15;
    v20 = v67 + 1;
    v21 = a0123456789abcd[(unsigned __int8)*v11 >> 4];
    v22 = v66;
    if ( v66 != v68 )
      v19 = v68[0];
    if ( v20 > v19 )
    {
      v53 = v67 + 1;
      v52 = a0123456789abcd[(unsigned __int8)*v11 >> 4];
      std::string::_M_mutate(&v66, v67, 0, 0, 1, "0123456789abcdef");
      v20 = v53;
      v21 = v52;
      v22 = v66;
    }
    *((_BYTE *)v22 + v18) = v21;
    v15 = 15;
    v67 = v20;
    v23 = a0123456789abcd[v17 & 0xF];
    *((_BYTE *)v66 + v18 + 1) = 0;
    v24 = v66;
    v25 = v67;
    if ( v66 != v68 )
      v15 = v68[0];
    if ( v67 + 1 > v15 )
    {
      v51 = v23;
      std::string::_M_mutate(&v66, v67, 0, 0, 1, "0123456789abcdef");
      v23 = v51;
      v24 = v66;
    }
    *((_BYTE *)v24 + v25) = v23;
    ++v11;
    v67 = v25 + 1;
  }
  v26 = std::__ostream_insert<char,std::char_traits<char>>(&std::cout, v66, v67, v15, v16, "0123456789abcdef");
  std::__ostream_insert<char,std::char_traits<char>>(v26, "\n", 1, v27, v28, v29);
  std::string::_M_dispose(&v66);
  sub_1A50((__int64)&v58);
  sub_1A50((__int64)&v55);
  sub_1A50((__int64)v54);
  return 0;
}

```

In short, the main function initializes constant **v3** to 37, reads flag.txt into the **src** variable, and then performs encryption. The encryption logic is **cipher\[i] = plain\[i] ⊕ mask\_i ⊕ 0x06**. Since it relies entirely on XOR operations, the decryption process is identical.

solver.py:

```python
hex_str = "849e87c7d2f6c8edc0f3102c2f05376d58674844b0d2908782fb09f3c1f83d46280e0a78604c604bbbdc869892d23ee4e6ec0036123103607a"
cipher = bytes.fromhex(hex_str)

def rol8(x, r):
    return ((x << r) | (x >> (8 - r))) & 0xFF

B = 37
K = rol8(3*B + 5, 2)  # 0xD1

plain = bytearray()
for i, c in enumerate(cipher):
    t = (13 * i) & 0xFF
    mask = ((t ^ K) - (i & 0xF)) & 0xFF
    plain.append(c ^ mask ^ 0x06)

print(plain.decode("latin1"))
```

if we run it, we get the flag:

<figure><img src="../../../.gitbook/assets/unknown (2).png" alt=""><figcaption></figcaption></figure>

#### Flag: SCH25{Whwn\_yhhhh\_jwago\_revvvvers\_semga\_nlaimu\_AAAA\_sellu}
