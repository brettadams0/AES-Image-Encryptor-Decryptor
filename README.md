# AES Image Encryptor/Decryptor

A small Tkinter desktop app that encrypts and decrypts image files with AES-256 in CBC mode. You
pick a file and type a password; the password is SHA-256'd into a 256-bit key, and a fresh random IV
is generated per encryption and written as the first 16 bytes of the output file.

## Requirements

Python 3, plus:

```sh
pip install -r requirements.txt   # Pillow, pycryptodome
```

Note that it is `pycryptodome`, not the long-abandoned `pycrypto` — both import as `Crypto`, so
installing the wrong one fails in confusing ways. Tkinter ships with CPython on Windows and macOS;
on Debian/Ubuntu it is a separate `python3-tk` package.

## Running it

```sh
python app.py
```

Enter a password, then use **Encrypt Image** or **Decrypt Image** to pick a file.

## What it does not do

The password is hashed straight into a key with a single unsalted SHA-256 pass — no KDF, no
iteration count, no per-file salt — so it is only as strong as the password itself and offers no
resistance to offline brute force. CBC gives confidentiality but not authentication: a tampered
ciphertext decrypts to garbage rather than being rejected. Fine for keeping casual eyes off a photo,
not a substitute for a real encrypted volume.

## License

MIT — see [LICENSE](LICENSE).
