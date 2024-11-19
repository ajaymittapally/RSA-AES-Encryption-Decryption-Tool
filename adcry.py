# New imports
import os
import ast
import tkinter as tk
import smtplib
from email.mime.text import MIMEText
from tkinter.simpledialog import askstring
from tkinter import messagebox, filedialog
from email.mime.multipart import MIMEMultipart
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as aes_padding
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode

# Aes Encryption Decryption

def generate_aes_key():
    return os.urandom(16)

def pad(data):
    padder = aes_padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    return padded_data

def unpad(data):
    unpadder = aes_padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(data) + unpadder.finalize()
    return unpadded_data

def aes_encrypt(plaintext, key):
    plaintext = pad(plaintext.encode('utf-8'))
    iv = b'\x00' * 16  # Initialization vector (IV) should be unique and unpredictable for each encryption
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return b64encode(iv + ciphertext).decode('utf-8')

def aes_decrypt(ciphertext, key):
    ciphertext = b64decode(ciphertext.encode('utf-8'))
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return unpad(plaintext).decode('utf-8')

# RSA encryption Decryption

def open_keys():
    public_key_path = 'keypairs/publicKey.pem'
    private_key_path = 'keypairs/privateKey.pem'
 
    with open(public_key_path, 'rb') as public_key_file:
        public_key_bytes = public_key_file.read()
        public_key = serialization.load_pem_public_key(public_key_bytes, backend=default_backend())
 
    with open(private_key_path, 'rb') as private_key_file:
        private_key_bytes = private_key_file.read()
        private_key = serialization.load_pem_private_key(private_key_bytes, password=None, backend=default_backend())
 
    return public_key, private_key

def rsa_encrypt(message, public_key):
    ciphertext = public_key.encrypt(
        message,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def rsa_decrypt(ciphertext, private_key):
    plaintext = private_key.decrypt(
        ciphertext,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext
# UI functions

def message_encryption():
    message = message_entry.get()
    publicKey, privateKey = open_keys()

    # Generate a temporary AES key
    aes_key = generate_aes_key()

    # Encrypt the message with AES
    ciphertext = aes_encrypt(message, aes_key)
    
    cipherkey = rsa_encrypt(aes_key, publicKey)
 
    # Combine the encrypted AES key and the encrypted message
    combined_ciphertext = f"{ciphertext}:{cipherkey}"

    entered_ciphertext.delete(0, tk.END)
    entered_ciphertext.insert(tk.END, combined_ciphertext)

    private_key_window = tk.Toplevel(window)
    private_key_window.title("Private Key")
    private_key_window.geometry("400x200")
    private_key_window.configure(background='#1C3012')

    private_key_label = tk.Label(private_key_window, text="Private Key:", font=("Segoe Script", 14), background='#AFE1AF')
    private_key_label.pack(pady=10)

    private_key_text = tk.Text(private_key_window, width=40, height=5)
    private_key_text.insert(tk.END, privateKey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode())

    private_key_text.pack()

    private_key_text.config(state=tk.DISABLED)

    # Saving private key to a file
    def save_private_key():
        file_path = filedialog.asksaveasfilename(defaultextension=".pem")
        if file_path:
            with open(file_path, 'w') as f:
                f.write(privateKey.save_pkcs1().decode())
            messagebox.showinfo("Success", "Private key has been saved")

    save_btn = tk.Button(private_key_window, text="Save Private Key", width=20, command=save_private_key, bg='#AFE1AF')
    save_btn.pack(pady=10)
    

# Decrypts the message using AES and then decrypts the RSA key with the private key
def message_decryption():
    combined_ciphertext = entered_ciphertext.get()

    # Split the combined ciphertext into encrypted AES key and encrypted message
    encrypted_message, encrypted_key = combined_ciphertext.rsplit(':', 1)

    privateKey_string = askstring("Private Key", "Enter private key:")

    if privateKey_string:
        private_key_bytes = privateKey_string.lstrip().encode()
        privateKey = serialization.load_pem_private_key(
            private_key_bytes,
            password=None,
            backend=default_backend()
        )

        try:
            # Use ast.literal_eval for safer evaluation
            aes_key = rsa_decrypt(ast.literal_eval(encrypted_key), privateKey)

            # Decrypt the message with AES
            decrypted_message = aes_decrypt(encrypted_message, aes_key)

            if decrypted_message:
                plaintext_entry.delete(0, tk.END)
                plaintext_entry.insert(tk.END, decrypted_message)
            else:
                messagebox.showerror("Error", "Could not decrypt message")
        except (ValueError, TypeError, SyntaxError) as e:
            messagebox.showerror("Error", f"Error decrypting AES key: {e}")
    else:
        messagebox.showerror("Error", "Private key has not been provided")
        
# Exits application
def exit_program():
    window.destroy()
# UI Code
# Opens user's email in browser
def open_gmail():
    webbrowser.open("https://mail.google.com/")
    
# Sends the email
def send_email():
    # Defines sender and receiver
    sender_email = 'crystalafnan@gmail.com'
    recipient_email = email_entry.get()
    ciphered_message = entered_ciphertext.get()

    if not recipient_email:
        messagebox.showerror("Error", "Recipient email is not provided")
        return

    # Creating a MIME message
    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = recipient_email
    message["Subject"] = "Secret Encrypted Message"
     # Adds the ciphertext to the body of the email
    message.attach(MIMEText(ciphered_message, "plain"))

    try:
        # Sends the email using SMTP server
        smtp_server = "smtp.gmail.com"
        smtp_port = 587
        smtp_username = "ajaymittapally70@gmail.com"
        smtp_password = "nvrb wgbx lanr kpjp"

        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_username, smtp_password)
            server.send_message(message)

        messagebox.showinfo("Success", "Email has been sent")
    except Exception as e:
        messagebox.showerror("Error", str(e))

    
window = tk.Tk()
window.title("RSA & AES Encryption/Decryption")
window.geometry("500x600")

content_frame = tk.Frame(window, bg='#1C3012', bd=5000)  # 45ADA8 ORIGINAL
content_frame.place(relx=0.5, rely=0.5, anchor='center')

label = tk.Label(content_frame, text="Pick choose an option:", font=("Hamiltone Signature", 14), bg='#9DE0AD')
label.pack(pady=10)


encrypt_btn = tk.Button(content_frame, text="Encrypt Message", width=20, command=message_encryption, bg='#AFE1AF')
encrypt_btn.pack(pady=10)

decrypt_btn = tk.Button(content_frame, text="Decrypt Message", width=20, command=message_decryption, bg='#AFE1AF')
decrypt_btn.pack()

gmail_btn = tk.Button(content_frame, text="Open Gmail", width=20, command=open_gmail, bg='#AFE1AF')
gmail_btn.pack(pady=10)

exit_btn = tk.Button(content_frame, text="Quit", width=20, command=exit_program, bg='#AFE1AF')
exit_btn.pack()

message_label = tk.Label(content_frame, text=" Message:", font=("Ghetto Display", 12), bg='#9DE0AD')
message_label.pack(pady=10)

message_entry = tk.Entry(content_frame, width=50)
message_entry.pack()

ciphertext_label = tk.Label(content_frame, text="Enter Ciphertext:", font=("Peristiwa Calligraphic", 12), bg='#9DE0AD')
ciphertext_label.pack(pady=10)

entered_ciphertext = tk.Entry(content_frame, width=50)
entered_ciphertext.pack()

plaintext_label = tk.Label(content_frame, text="Decrypted Plaintext:", font=("Segoe Script", 12), bg='#9DE0AD')
plaintext_label.pack(pady=10)

plaintext_entry = tk.Entry(content_frame, width=50)
plaintext_entry.pack()

email_label = tk.Label(content_frame, text="Enter Recipient's Email:", font=("Segoe Script", 12), bg='#9DE0AD')
email_label.pack(pady=10)

email_entry = tk.Entry(content_frame, width=50)
email_entry.pack()

send_email_btn = tk.Button(content_frame, text="Send", font=("Calibri", 12, 'bold'), width=20, command=send_email, bg='#AFE1AF')
send_email_btn.pack(pady=10)

window.mainloop()