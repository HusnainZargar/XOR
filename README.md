# GhostXOR - XOR Encryptor v2.0.0

A custom XOR-based encryption tool that encrypts and decrypts data using XOR operations combined with bit-flipping for extra obfuscation. 

---

## 📌 Features

✅ XOR Encryption + Bit Flipping  
✅ Hex-encoded encrypted output  
✅ Colorful CLI Output  
✅ Works with any file size (dynamic memory)  
✅ Cross-platform source code (Linux, macOS)

---

## 🔍 How it Works 

1. Read file into memory
2. For each byte:
   - Flip bits (NOT)
   - XOR with key byte
3. Convert binary → hex (during encryption)
4. Reverse the steps for decryption

✔ Key is reused cyclically
✔ No fixed size limitation

---

## 🛠️ Compile & Run

1. Compile the program:
```bash
gcc xor.c -o Xor-Encryptor
```
2. Run the program:
   
```bash
./Xor-Encryptor
```

---

## 📌 Usage
```
./Xor-Encryptor -e -k <KEY> -f <FILE>   # Encrypt
```
```
./Xor-Encryptor -d -k <KEY> -f <FILE>   # Decrypt
```

---

## 🔑 Options
| Flag        | Description             |
| ----------- | ----------------------- |
| `-e`        | Encrypt the file        |
| `-d`        | Decrypt the file        |
| `-k <KEY>`  | Secret key used for XOR |
| `-f <FILE>` | Path to input file      |
| `-h`        | Show help menu          |

---

## ⚠️ Disclaimer

This encryption method is not intended for secure cryptography.
It is for learning, obfuscation, and fun CTF usage only.

Use responsibly ✅

## 👨‍💻 Author

Muhammad Husnain Zargar
Version: 2.0.0

---

⭐ Like this project?

Give it a star ⭐ on GitHub to support development!
