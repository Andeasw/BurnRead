# BurnRead

BurnRead is a simple self-destructing message service written in PHP.

It allows users to create encrypted messages that can be shared via a link and will be destroyed automatically based on predefined rules.

---

## Features

- ✏️ Create and edit text messages
- 🔗 Share messages via a unique link
- ⏱️ Set expiration time
- 🔢 Limit number of views
- 🔐 Optional password protection
- 🔒 End-to-end encryption using AES-256
- 🔥 Message is permanently deleted after expiration or view limit is reached

---

## Encryption

All message content is encrypted using **AES-256** before storage.  
The server never stores plaintext message content.

---

## Requirements

- PHP >= 7.0
- Web server (Nginx / Apache)
---

## Basic Workflow

1. User creates a message and sets expiration rules
2. Message is encrypted and stored
3. A one-time access link is generated
4. Message is decrypted only when accessed
5. Message is destroyed after conditions are met

---

## Security Notice

This project is a lightweight implementation intended for temporary message sharing.  
It has not undergone a formal security audit.

Do not use it for highly sensitive or critical data without additional security hardening.

---

## License

MIT License
