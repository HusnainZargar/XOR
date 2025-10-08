# XOR Encryptor

## Description
This is a simple XOR-based encryptor and decryptor written in C. It allows the user to encrypt a plaintext message into a hexadecimal ciphertext using a key, and also decrypt a hexadecimal ciphertext back into plaintext using the same key.

---

## Features
- Encrypt any text message using XOR and a custom key.
- Output encrypted data as a hexadecimal string.
- Decrypt hexadecimal XOR ciphertext back to the original message.
- Supports messages and keys up to 256 characters.
- Simple console-based interface with user-friendly prompts.

---

## How It Works
- **Encryption:** Each byte of the message is XORed with the corresponding byte of the key (repeating the key if shorter than the message). The result is converted to a hexadecimal string.
- **Decryption:** The hexadecimal ciphertext is converted back into bytes, then XORed with the key to retrieve the original message.

---

## Usage
1. Compile the program:
```
gcc xor_encryptor.c -o xor_encryptor
```
2. Run the program:
   
```
./xor_encryptor
```
