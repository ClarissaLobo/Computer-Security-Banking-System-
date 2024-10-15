from hashlib import algorithms_available
from multiprocessing import context
import socket
import ssl
import threading
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key

def load_user_credentials(file_path):
    credentials = {}
    with open(file_path, 'r') as file:
        for line in file:
            username, password = line.strip().split(' ')
            credentials[username] = {'password': password}
    return credentials

#Load Password text file
user_credentials = load_user_credentials('password.txt')


# Function to load RSA private key
def load_bank_private_key(file_path):
    with open(file_path, 'rb') as file:
        private_key = file.read()
    return load_pem_private_key(private_key, password=None, backend=default_backend())

bank_private_key = load_bank_private_key('bank_private_key.pem')


def handle_client(client_socket, addr, ssl_socket):
    global authenticated_user_id
    try:
        authenticated = False
        while not authenticated:
            encrypted_symmetric_key = ssl_socket.recv(1024)
            symmetric_key = bank_private_key.decrypt(
                encrypted_symmetric_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            # print("Generated Symmetric Key:", symmetric_key.hex())
            
            encrypted_user_data = ssl_socket.recv(1024)
            decrypted_user_data = decrypt_with_symmetric_key(encrypted_user_data, symmetric_key)
        
            user_id, password = decrypted_user_data.split(b'||')
            authenticated_user_id = user_id.decode()

            if user_credentials.get(user_id.decode()):
                stored_password = user_credentials[user_id.decode()]['password']
                if stored_password == password.decode():
                    ssl_socket.send(b"ID and password are correct.")
                    authenticated = True
                else:
                    ssl_socket.send(b"Password is incorrect. Please try again.")
            else:
                ssl_socket.send(b"ID is incorrect. Please try again.")
            
        if authenticated:
            while True:
                transfer_info = ssl_socket.recv(1024)
                if len(transfer_info) == 0:
                    continue
                if transfer_info==b'1':
                    transfer_info = ssl_socket.recv(1024)
                    selected_account, recipient_id, amount = transfer_info.decode().split(':')
                    recipient_exists = False
                    with open('balance.txt', 'r') as balance_file:
                        for line in balance_file:
                            user_info = line.strip().split()
                            if user_info[0] == recipient_id:
                                recipient_exists = True
                                break

                    if recipient_exists:
                        with open('balance.txt', 'r+') as balance_file:
                            lines = balance_file.readlines()
                            balance_updated = False

                            for index, line in enumerate(lines):
                                user_info = line.strip().split()
                                if user_info[0] == authenticated_user_id:
                                    balance = float(user_info[int(selected_account)])
                                    amount = float(amount)
                                    if balance >= amount:
                                        new_balance = balance - amount
                                        user_info[int(selected_account)] = str(new_balance)
                                        updated_line = ' '.join(user_info) + '\n'
                                        lines[index] = updated_line
                                        balance_updated = True

                                if user_info[0] == recipient_id:
                                    balance = float(user_info[int(selected_account)])
                                    amount = float(amount)
                                    new_balance = balance + amount
                                    user_info[int(selected_account)] = str(new_balance)
                                    updated_line = ' '.join(user_info) + '\n'
                                    lines[index] = updated_line

                            if balance_updated:
                                balance_file.seek(0)
                                balance_file.writelines(lines)
                                balance_file.truncate()
                                ssl_socket.send(b"Your transaction is successful")
                            else:
                                ssl_socket.send(b"Your account does not have enough funds")
                    else:
                        ssl_socket.send(b"The recipient's ID does not exist")
                        
                elif transfer_info==b'2':
                    balances = check_account_balances(authenticated_user_id)
                    ssl_socket.send(balances.encode())  
                elif transfer_info==b'3':
                    ssl_socket.close()
                    print(f"Connection closed from {addr[0]}:{addr[1]}")
                    break  
          
    finally:
        ssl_socket.close()

# Function to check account balances
def check_account_balances(user_id):
    with open('balance.txt', 'r') as balance_file:
        for line in balance_file:
            user_info = line.strip().split()
            if user_info[0] == user_id:
                return f"Your savings account balance: {user_info[1]}\nYour checking account balance: {user_info[2]}"
    return "Account not found"

def decrypt_with_symmetric_key(data, key):
    iv = data[:16]  
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(data[16:]) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    return unpadded_data

def bank_server(server_name,port_number):
    
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile='clari_cert.pem', keyfile='clari_key.pem', password='1234')  
    server_socket = socket.socket()
    server_socket.bind(('', int(port_number)))
    server_socket.listen(5)

    print("Bank Server is running...")

    while True:
        conn, addr = server_socket.accept()
        print(f"Connected to {addr[0]}:{addr[1]}")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile='clari_cert.pem', keyfile='clari_key.pem', password='1234')
        ssl_socket = context.wrap_socket(conn, server_side=True)
        if addr:
            thread = threading.Thread(target=handle_client, args=(conn,addr,ssl_socket))
            thread.start()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python bank.py <Bank server’s port number>")
    else:
        host = socket.gethostname()
        bank_server(host,int(sys.argv[1]))
