Name:Clarissa Lobo
------------------

Email Address: clobo1@binghamton.edu
------------------------------------

Programming Language: Python
--------------------------------------

Code for performing encryption/decryption
----------------------------------------------
RSA Algorithm
-In my program I have used RSA encryption and decryption for exchanging a symmetric key securely between the bank server and ATM client.
-The bank's public key is used for encrypting the symmetric key before sending it to the server
-The bank's private key is used for decrypting the received symmetric key on the server side.
-RSA encryption/decryption is utilized during the initial authentication process.

AES Algorithm
-I have used AES encryption and decryption for securing the actual data transmission between the ATM client and the bank server
-AES uses a generated symmetric key for encryption and decryption which is exchanged securely using RSA.

Tested the code on remote.cs.binghamton.edu: YES
--------------------------------------------

How to execute the program:
---------------------------
Step-1: Execute the Bank.py program to start the bank server first using the command: python3 Bank.py <server_port> (5637 is my port number)

Step-2: Next, Execute the Atm.py program to start the Atm Transaction using the command: python3 Atm.py <server_domain> <server_port>

Step-4: Once the atm has established a connection with the bank server, it will prompt the user for an ID and password.
The atm will then send this information to the bank server for authentication and encrypts the data with the key and then decrypt server side.


Following files shared:
----------------------------------
Atm.py
Bank.py
balance text file
password text file
bank private key
bank public key
certificate for conn
key for conn



