---
description: forensics challenge
---

# easy-pcap

<figure><img src="../../../../.gitbook/assets/image (9).png" alt=""><figcaption></figcaption></figure>

given a pcap file

<figure><img src="../../../../.gitbook/assets/image (1) (1).png" alt=""><figcaption></figcaption></figure>

then I export HTTP object, then I got these files

<figure><img src="../../../../.gitbook/assets/image (2) (1).png" alt=""><figcaption></figcaption></figure>

then I cat all receive files

<figure><img src="../../../../.gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

I see here there's a few base64 string and a hex. Then I decrypt all base64 strings

<figure><img src="../../../../.gitbook/assets/image (4) (1).png" alt=""><figcaption></figcaption></figure>

Then I got these two strings. Then I convert the hex to ascii and got this

<figure><img src="../../../../.gitbook/assets/image (5) (1).png" alt=""><figcaption></figcaption></figure>

I got the first part of the flag. Then proceed to investigate other files

<figure><img src="../../../../.gitbook/assets/image (6) (1).png" alt=""><figcaption></figcaption></figure>

The send files doesn't seem too interesting. How about the last file

<figure><img src="../../../../.gitbook/assets/image (7) (1).png" alt=""><figcaption></figcaption></figure>

hmmm it's a png file, interesting. So I opened the png file

<figure><img src="../../../../.gitbook/assets/image (8) (1).png" alt=""><figcaption></figcaption></figure>

I see this is a kuroko no basuke image. then I proceed to use stegsolve on it

<figure><img src="../../../../.gitbook/assets/image (9) (1).png" alt=""><figcaption></figcaption></figure>

I got the second part of the flag. Then I proceed to investigate this picture further

<figure><img src="../../../../.gitbook/assets/image (10).png" alt=""><figcaption></figcaption></figure>

there's a file inside this png file. Then I extract it using binwalk then got these two files.&#x20;

<figure><img src="../../../../.gitbook/assets/image (11).png" alt=""><figcaption></figcaption></figure>

then I extract the 7zip file using **ilovekuroko** as the password

<figure><img src="../../../../.gitbook/assets/image (12).png" alt=""><figcaption></figcaption></figure>

all the extracted files went to bomb folder

<figure><img src="../../../../.gitbook/assets/image (13).png" alt=""><figcaption></figcaption></figure>

the bomb folder seemingly just a bunch of strings to make it confusing. but there's a secret file amidst all of this

<figure><img src="../../../../.gitbook/assets/image (14).png" alt=""><figcaption></figcaption></figure>

then I got the last part of the flag

#### Flag: hacktoday{y0u\_kn0w\_mY\_s3Cr3t\_w00psi33}
