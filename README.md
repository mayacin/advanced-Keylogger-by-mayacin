# Keylogger with Encryption and Decryption

The code demonstrates how a keylogger can capture keystrokes, log them, encrypt the log file, and then email the encrypted log. The decryption feature allows you to view the logs in a readable format.

**Important: This code is for educational purposes only.**
- **Do not use this script on devices without explicit permission.**
- **Always respect privacy and legal boundaries.**

## Features
- Logs keystrokes in real time.
- Encrypts the log files using symmetric encryption (Fernet).
- Periodically sends encrypted log files via email.
- Decrypts encrypted log files for analysis.

## Requirements
- Python 3.x
- Install dependencies:
 pip install pynput pyperclip mss sounddevice scipy cryptography requests
