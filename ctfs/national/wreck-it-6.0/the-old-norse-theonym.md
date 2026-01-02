# The-Old-Norse-Theonym

<figure><img src="../../../.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

Given an ELF file and flag.txt.enc. immediately decompile the ELF using ida and got these functions:

main::main

```c
char __fastcall main::main(_QWORD *a1)
{
  __int64 executable_name; // rax
  __int64 v2; // rdx
  char result; // al
  __int64 v4; // rax
  __int128 v5; // [rsp+40h] [rbp-158h]
  __int64 v6; // [rsp+A0h] [rbp-F8h]
  __int64 v7; // [rsp+A8h] [rbp-F0h]
  _DWORD v8[2]; // [rsp+B8h] [rbp-E0h] BYREF
  __int64 v9; // [rsp+C0h] [rbp-D8h] BYREF
  __int128 v10; // [rsp+C8h] [rbp-D0h]
  __int64 v11; // [rsp+F0h] [rbp-A8h]
  __int128 v12; // [rsp+100h] [rbp-98h] BYREF
  __int64 v13; // [rsp+110h] [rbp-88h]
  __int64 v14; // [rsp+118h] [rbp-80h]
  _DWORD v15[2]; // [rsp+120h] [rbp-78h] BYREF
  __int64 v16; // [rsp+128h] [rbp-70h] BYREF
  unsigned int v17; // [rsp+130h] [rbp-68h]
  __int64 v18; // [rsp+140h] [rbp-58h]
  unsigned int v19; // [rsp+14Ch] [rbp-4Ch] BYREF
  __int64 v20; // [rsp+150h] [rbp-48h]
  __int64 v21; // [rsp+158h] [rbp-40h]
  void *v22; // [rsp+160h] [rbp-38h]
  __int64 v23; // [rsp+168h] [rbp-30h]
  _BYTE *v24; // [rsp+170h] [rbp-28h]
  __int64 v25; // [rsp+178h] [rbp-20h]
  _BYTE v26[24]; // [rsp+180h] [rbp-18h] BYREF

  v26[23] = -123;
  v26[22] = 113;
  v26[21] = 70;
  v26[20] = -82;
  v26[19] = -33;
  v26[18] = 3;
  v26[17] = -62;
  v26[16] = 117;
  v26[15] = 98;
  v26[14] = -114;
  v26[13] = 63;
  v26[12] = -26;
  v26[11] = 117;
  v26[10] = -32;
  v26[9] = -76;
  v26[8] = -43;
  v26[7] = 113;
  v26[6] = -112;
  v26[5] = 112;
  v26[4] = 52;
  v26[3] = -84;
  v26[2] = 63;
  v26[1] = -92;
  v26[0] = 41;
  v25 = 24;
  v24 = v26;
  v23 = 1;
  v22 = &unk_4162B9;
  executable_name = main::get_executable_name((__int64)a1);
  v21 = v2;
  v20 = executable_name;
  v19 = 0;
  v18 = os::open(&unk_4162B9, 1, 0, 0, &v19, a1);
  v17 = v19;
  v16 = v18;
  v15[1] = 0;
  v15[0] = 0;
  result = (unsigned __int8)__equal_1905637414496559711(&v16, v15) == 0;
  if ( !result )
  {
    v4 = *a1;
    v14 = a1[1];
    v13 = v4;
    v12 = 0;
    v11 = os::read_dir(v17, -1, v4, v14, &v12);
    v10 = v12;
    v9 = v11;
    v8[1] = 0;
    v8[0] = 0;
    if ( (unsigned __int8)__equal_1905637414496559711(&v9, v8) )
    {
      v7 = *((_QWORD *)&v10 + 1);
      v6 = -1;
      while ( ++v6 < v7 )
      {
        v5 = *(_OWORD *)(v10 + 72 * v6 + 16);
        if ( !(unsigned __int8)BYTE12(*(_OWORD *)(v10 + 72 * v6 + 32))
          && !main::should_skip_file(v5, *((__int64 *)&v5 + 1), v20, v21, (__int64)a1) )
        {
          main::encrypt_file(v5, *((__int64 *)&v5 + 1), (__int64)v24, v25, a1);
          os::remove(v5, *((_QWORD *)&v5 + 1), a1);
        }
      }
      runtime::delete_slice_proc_array___os::File_Info_allocator_runtime::Allocator_loc_runtime::Source_Code_Location_____runtime::Allocator_Error_(
        v10,
        *((_QWORD *)&v10 + 1),
        *a1,
        a1[1],
        &off_4162C0);
      return os::close(v17, a1);
    }
    else
    {
      return os::close(v17, a1);
    }
  }
  return result;
}

```

Main::encrypt\_file

```c
char __fastcall main::encrypt_file(__int64 a1, __int64 a2, __int64 a3, __int64 a4, _QWORD *a5)
{
  __int64 v5; // rax
  char entire_file_from_filename; // al
  __int64 v8; // rax
  __int64 v9; // rax
  __int128 v13; // [rsp+B8h] [rbp-250h]
  __int128 v14; // [rsp+E0h] [rbp-228h] BYREF
  __int64 v15; // [rsp+F0h] [rbp-218h]
  __int64 v16; // [rsp+F8h] [rbp-210h]
  _QWORD *v17; // [rsp+100h] [rbp-208h]
  __int64 v18; // [rsp+108h] [rbp-200h]
  _QWORD v19[6]; // [rsp+110h] [rbp-1F8h] BYREF
  _BYTE s[258]; // [rsp+146h] [rbp-1C2h] BYREF
  __int128 v21; // [rsp+248h] [rbp-C0h]
  __int128 v22; // [rsp+270h] [rbp-98h] BYREF
  __int64 v23; // [rsp+280h] [rbp-88h]
  __int64 v24; // [rsp+288h] [rbp-80h]
  char v25; // [rsp+297h] [rbp-71h]
  __int128 v26; // [rsp+298h] [rbp-70h]
  __int128 v27; // [rsp+2C0h] [rbp-48h] BYREF
  __int64 v28; // [rsp+2D0h] [rbp-38h]
  __int64 v29; // [rsp+2D8h] [rbp-30h]
  __int64 v30; // [rsp+2E8h] [rbp-20h]
  __int64 v31; // [rsp+2F0h] [rbp-18h]
  __int64 v32; // [rsp+2F8h] [rbp-10h]
  __int64 v33; // [rsp+300h] [rbp-8h]

  v32 = a1;
  v33 = a2;
  v31 = a4;
  v30 = a3;
  v5 = *a5;
  v29 = a5[1];
  v28 = v5;
  v27 = 0;
  entire_file_from_filename = os::read_entire_file_from_filename(
                                a1,
                                a2,
                                v5,
                                v29,
                                (unsigned int)&off_416110,
                                (unsigned int)&v27,
                                (__int64)a5);
  v26 = v27;
  v25 = entire_file_from_filename;
  if ( entire_file_from_filename != 1 )
    return 0;
  v8 = *a5;
  v24 = a5[1];
  v23 = v8;
  v22 = 0;
  runtime::make_slice_proc_T____u8_len_int_allocator_runtime::Allocator_loc_runtime::Source_Code_Location_______u8__runtime::Allocator_Error_(
    *((_QWORD *)&v26 + 1),
    v8,
    v24,
    &off_416140,
    &v22);
  v21 = v22;
  memset(s, 0, sizeof(s));
  main::init((__int64)s, a3, a4);
  main::crypt((__int64)s, v26, *((__int64 *)&v26 + 1), v21, *((__int64 *)&v21 + 1), (__int64)a5);
  v19[3] = 4;
  v19[2] = ".enc";
  v17 = v19;
  v18 = 2;
  v19[1] = a2;
  v19[0] = a1;
  v19[4] = v19;
  v19[5] = 2;
  v9 = *a5;
  v16 = a5[1];
  v15 = v9;
  v14 = 0;
  strings::concatenate((unsigned int)v19, 2, v9, v16, (unsigned int)&off_416170, (unsigned int)&v14, (__int64)a5);
  v13 = v14;
  if ( (unsigned __int8)os::write_entire_file(v14, *((_QWORD *)&v14 + 1), v21, *((_QWORD *)&v21 + 1), 1, a5) == 1 )
  {
    runtime::delete_string(v13, *((_QWORD *)&v13 + 1), *a5, a5[1], &off_416230);
    runtime::delete_slice_proc_array___u8_allocator_runtime::Allocator_loc_runtime::Source_Code_Location_____runtime::Allocator_Error_(
      v21,
      *((_QWORD *)&v21 + 1),
      *a5,
      a5[1],
      &off_416260);
    runtime::delete_slice_proc_array___u8_allocator_runtime::Allocator_loc_runtime::Source_Code_Location_____runtime::Allocator_Error_(
      v26,
      *((_QWORD *)&v26 + 1),
      *a5,
      a5[1],
      &off_416290);
    return 1;
  }
  else
  {
    runtime::delete_string(v13, *((_QWORD *)&v13 + 1), *a5, a5[1], &off_4161A0);
    runtime::delete_slice_proc_array___u8_allocator_runtime::Allocator_loc_runtime::Source_Code_Location_____runtime::Allocator_Error_(
      v21,
      *((_QWORD *)&v21 + 1),
      *a5,
      a5[1],
      &off_4161D0);
    runtime::delete_slice_proc_array___u8_allocator_runtime::Allocator_loc_runtime::Source_Code_Location_____runtime::Allocator_Error_(
      v26,
      *((_QWORD *)&v26 + 1),
      *a5,
      a5[1],
      &off_416200);
    return 0;
  }
}

```

Main::init

```c
__int64 __fastcall main::init(__int64 a1, __int64 a2, __int64 a3)
{
  __int64 result; // rax
  char v4; // dl
  char v5; // [rsp+2Fh] [rbp-D9h]
  char v6; // [rsp+77h] [rbp-91h]
  __int64 v8; // [rsp+B8h] [rbp-50h]
  __int64 v9; // [rsp+C0h] [rbp-48h]
  unsigned __int8 v10; // [rsp+D7h] [rbp-31h]
  __int64 v11; // [rsp+E0h] [rbp-28h]
  __int64 v12; // [rsp+E8h] [rbp-20h]

  v12 = 0;
  v11 = 0;
  while ( v12 < 256 )
  {
    runtime::bounds_check_error(
      "/mnt/d/smth/Programming/CySec/Prob/Set/Wreckit/Reverse Engineering/The-Old-Norse-theonym/main.odin",
      98,
      16,
      17,
      v12,
      256);
    *(_BYTE *)(a1 + v12) = v12;
    ++v12;
    ++v11;
  }
  result = a3;
  *(_BYTE *)(a1 + 256) = 0;
  *(_BYTE *)(a1 + 257) = 0;
  v10 = 0;
  v9 = 0;
  v8 = 0;
  while ( v9 < 256 )
  {
    runtime::bounds_check_error(
      "/mnt/d/smth/Programming/CySec/Prob/Set/Wreckit/Reverse Engineering/The-Old-Norse-theonym/main.odin",
      98,
      26,
      25,
      v9,
      256);
    v6 = *(_BYTE *)(a1 + v9) + v10;
    if ( !a3 )
      BUG();
    runtime::bounds_check_error(
      "/mnt/d/smth/Programming/CySec/Prob/Set/Wreckit/Reverse Engineering/The-Old-Norse-theonym/main.odin",
      98,
      26,
      34,
      v9 % a3,
      a3);
    v10 = *(_BYTE *)(a2 + v9 % a3) + v6;
    runtime::bounds_check_error(
      "/mnt/d/smth/Programming/CySec/Prob/Set/Wreckit/Reverse Engineering/The-Old-Norse-theonym/main.odin",
      98,
      28,
      17,
      v9,
      256);
    runtime::bounds_check_error(
      "/mnt/d/smth/Programming/CySec/Prob/Set/Wreckit/Reverse Engineering/The-Old-Norse-theonym/main.odin",
      98,
      28,
      29,
      v10,
      256);
    runtime::bounds_check_error(
      "/mnt/d/smth/Programming/CySec/Prob/Set/Wreckit/Reverse Engineering/The-Old-Norse-theonym/main.odin",
      98,
      28,
      42,
      v10,
      256);
    v5 = *(_BYTE *)(a1 + v10);
    runtime::bounds_check_error(
      "/mnt/d/smth/Programming/CySec/Prob/Set/Wreckit/Reverse Engineering/The-Old-Norse-theonym/main.odin",
      98,
      28,
      54,
      v9,
      256);
    v4 = *(_BYTE *)(a1 + v9);
    *(_BYTE *)(a1 + v9) = v5;
    *(_BYTE *)(a1 + v10) = v4;
    ++v9;
    result = ++v8;
  }
  return result;
}

```

Main::crypt

```c
__int64 __fastcall main::crypt(__int64 a1, __int64 a2, __int64 a3, __int64 a4, __int64 a5, __int64 a6)
{
  __int64 result; // rax
  char byte; // [rsp+47h] [rbp-41h]
  __int64 i; // [rsp+50h] [rbp-38h]
  __int64 v12; // [rsp+58h] [rbp-30h]

  runtime::assert(a3 == a5, "Input and output slices must have same length", 45, &off_4160D0, a6);
  v12 = 0;
  for ( i = 0; ; ++i )
  {
    result = a3;
    if ( v12 >= a3 )
      break;
    byte = main::next_byte(a1);
    runtime::bounds_check_error(
      "/mnt/d/smth/Programming/CySec/Prob/Set/Wreckit/Reverse Engineering/The-Old-Norse-theonym/main.odin",
      98,
      47,
      16,
      v12,
      a5);
    runtime::bounds_check_error(
      "/mnt/d/smth/Programming/CySec/Prob/Set/Wreckit/Reverse Engineering/The-Old-Norse-theonym/main.odin",
      98,
      47,
      26,
      v12,
      a3);
    *(_BYTE *)(a4 + v12) = byte ^ *(_BYTE *)(a2 + v12);
    ++v12;
  }
  return result;
}

```

From the main::crypt function we can see the encryption uses **RC4**, which uses a key to generate a keystream, and then XORs the keystream with the file content.&#x20;

And from main::main we can see that the encryption key is hardcoded and is stored in an array **v26** with 24 bytes.

Since **RC4** is a symmetric stream cipher, the same key is used for both encryption and decryption. So using the key from the main::main, we can write a python script.

solver.py:

```python
import sys, re

KEY = bytes([0x29,0xA4,0x3F,0xAC,0x34,0x70,0x90,0x71,0xD5,0xB4,0xE0,0x75,
             0xE6,0x3F,0x8E,0x62,0x75,0xC2,0x03,0xDF,0xAE,0x46,0x71,0x85])
FLAG_RX = re.compile(br"WRECKIT60\{[0-9a-f]+\}")

def rc4(data, key):
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray(len(data))
    for n,b in enumerate(data):
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) & 0xFF]
        out[n] = b ^ K
    return bytes(out)

path = sys.argv[1] if len(sys.argv)>1 else "flag.txt.enc"
ct = open(path,"rb").read()
pt = rc4(ct, KEY)
open(path.replace(".enc","")+".dec","wb").write(pt)
m = FLAG_RX.search(pt)
print(m.group().decode() if m else "flag regex not found; cek file .dec")
```

When we run it, we get the flag:

<figure><img src="../../../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

#### Flag: WRECKIT60{1278644a3873e8874ea91a544a3cf07dc3f8e39210e847f0f222e16cbc665d2b}
