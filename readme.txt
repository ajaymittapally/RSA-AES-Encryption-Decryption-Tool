RSA & AES Encryption/Decryption Tool
This project is a simple encryption and decryption tool built using Python and Tkinter for the user interface. It supports AES (Advanced Encryption Standard) and RSA (Rivest-Shamir-Adleman) encryption algorithms for secure message encryption and decryption. The tool also provides functionality to send encrypted messages via email using SMTP.

Features
AES Encryption/Decryption:

Encrypt and decrypt messages using AES (with 128-bit key).
AES encryption uses a randomly generated key and encryption with CFB (Cipher Feedback) mode.
RSA Encryption/Decryption:

Encrypt the AES key using RSA public key encryption.
Decrypt the AES key with a private RSA key, then decrypt the message using AES.
Email Integration:

Send the encrypted message via SMTP to a recipient's email address.
Open Gmail in the browser to easily access and send emails.
Tkinter GUI:

User-friendly interface for encryption/decryption.
Text fields for inputting messages, ciphertext, and recipient email.
Buttons for encrypting, decrypting, sending emails, and quitting the application.
Installation
Prerequisites
Make sure you have the following installed:

Python 3.x
Required libraries: tkinter, cryptography, smtplib, base64, and ast. You can install these libraries using pip:
pip install 

Set up the RSA Key Pair
To use the RSA encryption/decryption functionality, you'll need a pair of RSA keys (public and private). You can generate your keys with the following command (or use pre-existing keys):

Usage
Running the Application
To start the application, run the following command:

python main.py
This will launch a Tkinter window with the following options:

Encrypt Message:

Enter a message in the input field and press "Encrypt Message" to encrypt the message.
The encrypted message will appear in the "Enter Ciphertext" field.
Decrypt Message:

Paste the combined ciphertext (AES encrypted message and RSA encrypted AES key) into the "Enter Ciphertext" field.
Enter the private key and press "Decrypt Message" to decrypt and view the original message.
Send Encrypted Message via Email:

Enter the recipient's email in the "Enter Recipient's Email" field.
Click "Send" to send the encrypted message to the specified email.
Open Gmail:

Opens the Gmail website in the browser to make it easier for the user to access their Gmail account.
Quit Application:

Closes the application.
Email Sending Configuration
The email functionality requires SMTP credentials for sending emails. In the provided code, the SMTP server settings are preconfigured for Gmail.

Important:

You must modify the email sender and SMTP credentials to match your Gmail account or any other email provider you wish to use.
If you are using Gmail, you may need to enable "Less Secure Apps" in your Gmail account settings or use App Passwords for better security.

How It Works
AES Encryption:

When you click "Encrypt Message", the plaintext message is first encrypted using AES with a randomly generated key.
The AES-encrypted message is then further encrypted by RSA using the public key.
The AES key (RSA-encrypted) and the AES ciphertext are concatenated and displayed in the "Enter Ciphertext" field.
AES Decryption:

To decrypt, the combined ciphertext is split into the AES ciphertext and the encrypted AES key.
The encrypted AES key is decrypted using the private RSA key, and the decrypted AES key is used to decrypt the AES ciphertext.
The original plaintext message is then displayed in the "Decrypted Plaintext" field.
Security Considerations
RSA Key Management:
Ensure that your private RSA key is securely stored and never shared. It's recommended to generate a new key pair for each user and use proper key storage techniques.

AES Key Security:
The AES key used for encrypting the message is randomly generated. It should never be hard-coded in the code or shared in plaintext.

Troubleshooting
Error: "Private key not provided":
This error occurs when the user does not enter the private key for decryption. Ensure the private key is entered correctly when decrypting the message.

Error: "Could not decrypt message":
This may happen if there is a mismatch in the RSA key used for encryption/decryption or if the ciphertext format is incorrect.

