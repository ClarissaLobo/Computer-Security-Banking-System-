from hashlib import algorithms_available, algorithms_guaranteed
import os
import socket
import ssl
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding
import warnings
import ssl

with open('bank_public_key.pem', 'rb') as file:
    bank_public_key = serialization.load_pem_public_key(file.read(), backend=default_backend())

#Generate symmetric key
def generate_symmetric_key():
    symmetric_key = os.urandom(32)
    return symmetric_key

symmetric_key = generate_symmetric_key()
# print("Generated Symmetric Key:", symmetric_key.hex())

def ignore_ssl_deprecation_warning(category, message):
    return message.filename is not None and 'ssl' in message.filename

#atm function
def atm_client(server_host, server_port):
    client_socket = socket.socket()
    warnings.simplefilter('ignore', DeprecationWarning)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    ssl_client_socket = context.wrap_socket(client_socket)

    ssl_client_socket.connect((server_host, server_port))
    try:
        print("Connected to the bank server.")

        authenticated = False
        while not authenticated:
            while True:
                #Enter the user Credentials
                user_id = input("Enter ID: ").encode()
                password = input("Enter password: ").encode()

                #Encrypt public key and symmetric key
                encrypted_symmetric_key = bank_public_key.encrypt(
                    symmetric_key,
                    padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                    )
                )
                #send encrypted symmetric key to bank
                ssl_client_socket.send(encrypted_symmetric_key)  

                data_to_encrypt = user_id + b'||' + password
                encrypted_data = encrypt_with_symmetric_key(data_to_encrypt, symmetric_key)
                #send encrypted id and password of user to bank for authentication
                ssl_client_socket.send(encrypted_data)  
                response = ssl_client_socket.recv(1024).decode()

                if response == "ID and password are correct.":
                    authenticated = True
                    print("Authentication successful.")
                    break
                else:
                    print("ID or password is incorrect. Please try again.")
        while True:
            # Display the main menu
            print("Please select one of the following actions (enter 1, 2, or 3):")
            print("1. Transfer money")
            print("2. Check account balance")
            print("3. Exit")
                        
            selected_option = input("Enter your choice: ")
            if selected_option not in ('1', '2', '3'):
                print("Incorrect input. Please enter 1, 2, or 3.")
                continue  
                    
            if selected_option == '1':
                selected_account = None
                while selected_account not in ('1', '2'):
                    print("Please select an account (enter 1 or 2):")
                    print("1. Savings")
                    print("2. Checking")

                    selected_account = input("Enter your choice: ")

                    if selected_account not in ('1', '2'):
                        print("Incorrect input. Please select either the savings or checking account.")

                recipient_id = input("Enter the recipient's ID: ")
                amount = input("Enter the amount to be transferred: ")
                transfer_info=f"{selected_option}".encode()
                ssl_client_socket.send(transfer_info)
                transfer_info = f"{selected_account}:{recipient_id}:{amount}".encode()
                ssl_client_socket.send(transfer_info)  
                
                recipient_response = ssl_client_socket.recv(1024).decode()
                print(recipient_response)                

                if recipient_response == "The recipient's ID does not exist":
                    print("Recipient's ID does not exist. Please try again.")
                elif recipient_response == "Your transaction is successful":
                    continue
                elif recipient_response == "Your account does not have enough funds":
                    continue                      
        
            elif selected_option == '2':
                transfer_info = f"{selected_option}".encode()
                ssl_client_socket.send(transfer_info)  
                balances = ssl_client_socket.recv(1024).decode()  
                print(balances)

            elif selected_option == '3':
                close_signal = "3".encode()
                ssl_client_socket.send(close_signal)  
                break  
                        
            else:
                print("Invalid option. Please enter 1, 2, or 3.")
    finally:
        ssl_client_socket.close()

#Funtion for encryption
def encrypt_with_symmetric_key(data, key):
    iv = os.urandom(16)  
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    ct = encryptor.update(padded_data) + encryptor.finalize()
    if len(ct) > len(key):
        raise ValueError("Ciphertext size exceeds RSA key size")
    return iv + ct  


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python atm.py <Bank server’s domain name> <Bank server’s port number>")
    else:
        atm_client(sys.argv[1], int(sys.argv[2]))
