import ftplib
from tkinter import messagebox
from filesplit.split import *
from filesplit.merge import Merge
import random
import base32hex
from Cryptodome.Cipher import AES, DES, PKCS1_OAEP, Blowfish
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from tkinter import *
from tkinter.ttk import *
from tkinter.filedialog import askopenfilename

# FTP server credentials
FTP_HOST = "192.168.1.6"
FTP_USER = "user"
FTP_PASS = "mariam"

# connect to the FTP server
ftp = ftplib.FTP()
ftp.connect(FTP_HOST)
ftp.login(FTP_USER, FTP_PASS)
# force UTF-8 encoding
ftp.encoding = "utf-8"

# Private key
private_key16 = get_random_bytes(16)
private_key8 = get_random_bytes(8)

# Setting up GUI
ws = Tk()
ws.title('Secure File Shared Storage')
ws.geometry('400x300')
ws.configure(bg='dark salmon')

# Set up upload button
choose_btn = Button(ws, text='Upload File', command=lambda: open_file())
choose_btn.grid(row=2, column=150)

# Initializing encryption options flag value
option = 1


# Choose file
def open_file():
    # Get the file path in string format
    file_path = askopenfilename(filetypes=[('Text Files', '*txt')])
    split = Split(file_path, "D:\Engineering Senior\Semester 9\Security\Project\Split Files")
    # Split every 50 bytes
    split.bysize(25)
    # Directory of split files
    directory = os.fsencode("D:\Engineering Senior\Semester 9\Security\Project\Split Files")

    for file in os.listdir(directory):
        split_file = os.fsdecode(file)
        if split_file.endswith(".txt"):
            plaintext_path = "D:/Engineering Senior/Semester 9/Security/Project/Split Files" + "/" + split_file

            with open(plaintext_path, "rb") as plain_file:
                plaintext = plain_file.read()

            # Generating a random encryption
            option = random.randint(1, 3)

            # Generating public and private keys
            key = RSA.generate(2048)
            private_key = key.export_key()
            file_out = open("master_key.pem", "wb")
            file_out.write(private_key)
            file_out.close()

            public_key = key.publickey().export_key()
            file_out = open("public.pem", "wb")
            file_out.write(public_key)
            file_out.close()

            # Setting up public key
            recipient_key = RSA.import_key(open("public.pem").read())
            session_key = private_key16

            # Encrypt the session key with the public RSA key
            cipher_rsa = PKCS1_OAEP.new(recipient_key)
            enc_session_key = cipher_rsa.encrypt(session_key)

            # Three Symmetric ciphers
            # AES Cipher EAX Mode
            if option == 1:
                # Encrypt the file
                cipher = AES.new(session_key, AES.MODE_EAX)
                ciphertext, tag = cipher.encrypt_and_digest(plaintext)

                with open(plaintext_path, 'wb') as file:
                    [file.write(x) for x in (enc_session_key, cipher.nonce, tag, ciphertext)]


            # DES Cipher OFB Mode
            elif option == 2:
                # Generating public and private keys
                key = RSA.generate(2048)
                private_key = key.export_key()
                file_out = open("master_key.pem", "wb")
                file_out.write(private_key)
                file_out.close()

                public_key = key.publickey().export_key()
                file_out = open("public.pem", "wb")
                file_out.write(public_key)
                file_out.close()

                # Setting up public key
                recipient_key = RSA.import_key(open("public.pem").read())
                session_key = private_key8

                # Encrypt the session key with the public RSA key
                cipher_rsa = PKCS1_OAEP.new(recipient_key)
                enc_session_key = cipher_rsa.encrypt(session_key)

                # Encrypt with DES OFB mode
                cipher = DES.new(session_key, DES.MODE_OFB)
                ciphertext = cipher.encrypt(plaintext)

                with open(plaintext_path, 'wb') as file:
                    [file.write(x) for x in (enc_session_key, ciphertext)]


            # Blowfish Cipher CTR Mode
            elif option == 3:
                # Encrypt the file
                cipher = Blowfish.new(session_key, Blowfish.MODE_CFB)
                ciphertext = cipher.encrypt(plaintext)
                global iv
                iv = cipher.iv

                with open(plaintext_path, 'wb') as file:
                    [file.write(x) for x in (enc_session_key, ciphertext)]

    # Merging the files after encryption
    merge = Merge("D:\Engineering Senior\Semester 9\Security\Project\Split Files",
                  "D:\Engineering Senior\Semester 9\FTP server", "test.txt")
    merge.merge()


# Download file
def download_file():
    # Get the public key from the user
    messagebox.showinfo("Decryption Key", "Please enter your public key")
    key_path = askopenfilename(filetypes=[('Key Files', '*pem')])
    # Get the data file to download
    messagebox.showinfo("Decryption Key", "Please enter choose a file to download")
    file_path = askopenfilename(filetypes=[('Text Files', '*txt')])

    if option == 1:
        # Decrypting
        private_key = RSA.import_key(open(key_path).read())

        # Decrypt the file
        with open(file_path, 'rb') as file:
            enc_session_key, nonce, tag, ciphertext = [file.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1)]

        cipher = AES.new(private_key16, AES.MODE_EAX, nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)

        # Save decrypted file locally
        with open('decrypted.txt', 'wb') as file:
            file.write(plaintext)

    elif option == 2:
        # Decrypting
        private_key = RSA.import_key(open(key_path).read())

        # Decrypt the file
        with open(file_path, 'rb') as file:
            enc_session_key, ciphertext = [file.read(x) for x in (private_key.size_in_bytes(), -1)]

        cipher = DES.new(private_key8, DES.MODE_OFB)
        plaintext = cipher.decrypt(ciphertext)

        # Save decrypted file locally
        with open('decrypted.txt', 'wb') as file:
            file.write(plaintext)

    elif option == 3:
        # Decrypting
        private_key = RSA.import_key(open(key_path).read())

        # Decrypt the file
        with open(file_path, 'rb') as file:
            enc_session_key, ciphertext = [file.read(x) for x in (private_key.size_in_bytes(), -1)]

        cipher = Blowfish.new(private_key16, Blowfish.MODE_CFB, iv)
        plaintext = cipher.decrypt(ciphertext)

        # Save decrypted file locally
        with open('decrypted.txt', 'wb') as file:
            file.write(plaintext)


download_btn = Button(ws, text='Download File', command=download_file)
download_btn.grid(row=3, column=150, columnspan=3, pady=10)

ws.mainloop()
ftp.quit()
