# prtg-decryptor

Install with [uv](https://github.com/astral-sh/uv).

~~~ bash
uv tool install git+https://github.com/dadevel/prtg-decryptor.git@main
~~~

Exfiltrate the file `C:\ProgramData\Paessler\PRTG Network Monitor\PRTG Configuration.dat` from PRTG.

Then decrypt the secrets offline.

~~~ bash
# Decrypt whole file
prtg-decryptor file ./configuration.dat -o out.xml

# Decrypt valuable information and generate a html file
prtg-decryptor file ./configuration.dat -o out.html --html

# Decrypt a blob
prtg-decryptor blob -g '{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}' AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH
~~~

References:

- [github.com/yobabyte/decryptocollection](https://github.com/yobabyte/decryptocollection)
