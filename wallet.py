#!/usr/bin/env python3

"""This is going to be your wallet. Here you can do several things:
- Generate a new address (public and private key). You are going
to use this address (public key) to send or recieve any transactions. You can
have as many addresses as you wish, but keep in mind that if you
lose its credential data, you will not be able to retrieve it.

- Send coins to another address
- Retrieve the entire blockchain and check your balance

If this is your first time using this script don't forget to generate
a new address and edit miner config file with it (only if you are
going to mine).

Timestamp in hashed message. When you send your transaction it will be recieved
by several nodes. If any node mine a block, your transaction will get added to the
blockchain but other nodes still will have it pending. If any node see that your
transaction with same timestamp was added, they should remove it from the
node_pending_transactions list to avoid it get processed more than 1 time.
"""

import socket
import time
import base64
import ecdsa
import errno
from json_tricks import dumps, loads
from miner_config import MINER_IP, MINER_PORT, MINER_ADDRESS, PEER_NODES

def welcome_msg():
    print("""       =========================================\n
        SIMPLE COIN v2.0.0 - BLOCKCHAIN SYSTEM\n
       =========================================\n\n
        You can find more help at: https://github.com/Scotchmann/SimpleCoin\n
        (Initial project you can find at https://github.com/cosme12/SimpleCoin)\n
        Make sure you are using the latest version or you may end in
        a parallel chain.\n\n\n""")


def wallet():
    response = False
    while response not in ["1","2","3"]:
        response = input("""What do you want to do?
        1. Generate new wallet
        2  Check balance
        3. Send coins to another wallet
        4. Check transactions\n""")
    if response == "1":
        # Generate new wallet
        print("""=========================================\n
IMPORTANT: save this credentials or you won't be able to recover your wallet\n
=========================================\n""")

        generate_ECDSA_keys()
    elif response == "2":

        wallet_to_check = input("Introduce your wallet address (public key)\n")
        check_balance(wallet_to_check)

    elif response == "3":
        addr_from = input("From: introduce your wallet address (public key)\n")
        private_key = input("Introduce your private key\n")
        addr_to = input("To: introduce destination wallet address\n")
        amount = input("Amount: number stating how much do you want to send\n")
        print("=========================================\n\n")
        print("Is everything correct?\n")
        print("From: {0}\nPrivate Key: {1}\nTo: {2}\nAmount: {3}\n".format(addr_from,private_key,addr_to,amount))
        response = input("y/n\n")
        if response.lower() == "y":
            send_transaction(addr_from,private_key,addr_to,amount)
    elif response == "4":
        check_transactions()


def send_transaction(addr_from,private_key,addr_to,amount):
    """Sends your transaction to different nodes. Once any of the nodes manage
    to mine a block, your transaction will be added to the blockchain. Dispite
    that, there is a low chance your transaction gets canceled due to other nodes
    having a longer chain. So make sure your transaction is deep into the chain
    before claiming it as approved!
    """
    #for fast debuging REMOVE LATER
    private_key="d9319751ce59ff9450f4c8b469738227bb34c26a9e94283e123c0be6fa494466"
    amount="1"
    addr_from="i7YqTe+slTO9f+MpPYTOrh8p52T21jxpZBf/RiVAS1QRnCel31hpzEfa1T29UWvWlEbzeReIzHG43TxkAnlw5w=="
    addr_to="i7YqTe+slTO9f+MpPYTOrh8p52T21jxpZBf/RiVAS1QRnCel31hpzEfa1T29UWvWlNEWADRESS"

    if len(private_key) == 64:
        signature,message = sign_ECDSA_msg(private_key)
        url     = (MINER_IP,MINER_PORT)
        payload = {"from": addr_from, "to": addr_to, "amount": amount, "signature": signature.decode(), "message": message}
        try:
            qSocket = socket.socket()
            qSocket.settimeout(2)
            qSocket.connect(url)
            qSocket.send(dumps(('txion', payload)).encode())

            data = b''
            while True:
                try:
                    packet = qSocket.recv(1024)
                    if not packet:
                        break
                    data += packet
                except socket.error as e:
                    break

            if data:
                print(data.decode())

            qSocket.close()

        except:
            print('Connection to '+str(url[0])+':'+str(url[1]) + ' failed.')
    else:
        print("Wrong address or key length! Verify and try again.")

def check_transactions():
    """Retrieve the entire blockchain. With this you can check your
    wallets balance. If the blockchain is to long, it may take some time to load.
    """
    res = requests.get(MINER_NODE_URL+'/blocks')
    print(res.text)

def check_balance(wallet_to_check):
    url     = (MINER_IP,MINER_PORT)
    try:
        qSocket = socket.socket()
        qSocket.connect(url)
        qSocket.settimeout(2)
        try:
            qSocket.send(dumps(('balance', wallet_to_check)).encode())
            data = b''
            while True:
                try:
                    packet = qSocket.recv(1024)
                    if not packet:
                        break
                    data += packet
                except socket.error as e:
                    break
            if data:
                data = loads(data.decode())
            else:
                print('balance fault')
                return None

            print('Your balance is: ' + str(float(data)))
            qSocket.close()
        except:
            print('fault')
    except:
        print('Connection to '+str(url[0])+':'+str(url[1]) + ' failed.')

def generate_ECDSA_keys():
    """This function takes care of creating your private and public (your address) keys.
    It's very important you don't lose any of them or those wallets will be lost
    forever. If someone else get access to your private key, you risk losing your coins.

    private_key: str
    public_ley: base64 (to make it shorter)
    """
    sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1) #this is your sign (private key)
    private_key = sk.to_string().hex() #convert your private key to hex
    vk = sk.get_verifying_key() #this is your verification key (public key)
    public_key = vk.to_string().hex()
    print("Private key: {0}".format(private_key))
    #we are going to encode the public key to make it shorter
    public_key = base64.b64encode(bytes.fromhex(public_key))
    #using decode() to remove the b'' from the printed string
    print("Wallet address / Public key: {0}".format(public_key.decode()))


def sign_ECDSA_msg(private_key):
    """Sign the message to be sent
    private_key: must be hex

    return
    signature: base64 (to make it shorter)
    message: str
    """
    #get timestamp, round it, make it string and encode it to bytes
    message=str(round(time.time()))
    bmessage = message.encode()
    sk = ecdsa.SigningKey.from_string(bytes.fromhex(private_key), curve=ecdsa.SECP256k1)
    signature = base64.b64encode(sk.sign(bmessage))
    return signature,message


if __name__ == '__main__':
    if MINER_IP == '':
        MINER_IP = socket.gethostbyname(socket.getfqdn())
    if MINER_PORT == 0:
        MINER_PORT = 5000
        
    welcome_msg()
    wallet()
    input("Press any key to exit...")
