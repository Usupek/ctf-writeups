# Ranger Shop

<figure><img src="../../../.gitbook/assets/image (26).png" alt=""><figcaption></figcaption></figure>

Given an ELF file, if we run it:

<figure><img src="../../../.gitbook/assets/image (25).png" alt=""><figcaption></figcaption></figure>

turns out it's a flag shop program. If we input negative number:

<figure><img src="../../../.gitbook/assets/unknown (3) (1).png" alt=""><figcaption></figcaption></figure>

turns out we can input negative numbers, but even though we got enough points, we still don't get the flag. So we proceed to decompile the file.

Because the decompiled functions are so long, I'll just summarize what the program does:

when the program ask for name:

```c
fgets(s, 64, stdin);
/* pengecekan karakter terlarang: membandingkan dengan string nptr, yang berisi */ 
/* set karakter tertentu seperti {}()|*& etc. Tapi bukan ';' atau spasi */
strncpy(user_name, s, 0xFu);
```

the name is stored in **user\_name** so it can be used later in menu option 5:

```c
__snprintf_chk(s, 256, 2, 256, "figlet %s", user_name);
system(s);
```

This is dangerous cause if the user's input is ';', the user can run any command, like for example if the user inputs 'a;sh', then the user can get a shell.

then in menu 4:

```c
v23 = strtol(s, 0, 10) * v22; // v22 = harga per item
if ( v23 > points ) { puts("Not enough"); }
else points -= v23;
```

if **strtol** results in negative number, negative v23 -> points -= (neg) -> points got up. This is what cause our point got up if we input a negative number.

so using two vulns we got, we can exploit the program:

<figure><img src="../../../.gitbook/assets/unknown (16).png" alt=""><figcaption></figcaption></figure>

#### Flag: RTRTNI25{c9f769e366ec795cecb3830212ea8e3d}
