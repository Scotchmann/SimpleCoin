
#!/usr/bin/env python3
import time
import select
import hashlib as hasher
import base64
from threading import Thread, Lock
from multiprocess import Process, Value, freeze_support
import ctypes
import ecdsa
import random
import eventlet
import os.path
import socket
from json_tricks import dumps, loads
import logging
import errno
import sys

logging.basicConfig()
logging.disable(logging.ERROR)

from miner_config import MINER_IP, MINER_PORT, MINER_ADDRESS, PEER_NODES
WORKERSNUMBER = 1
# Node's blockchain copy
BLOCKCHAIN = []

""" Store the transactions that this node has, in a list
If the node you sent the transaction adds a block
it will get accepted, but there is a chance it gets
discarded and your transaction goes back as if it was never
processed"""
NODE_PENDING_TRANSACTIONS = []

mutex = Lock()

TARGET = '000000'

class Block:
    def __init__(self, index, timestamp, data, previous_hash, prover):
        """Return a new Block object. Each block is "chained" to its previous
        by calling its unique hash.

        Args:
            index (int): Block number.
            timestamp (int): Block creation timestamp.
            data (str): Data to be sent.
            previous_hash(str): String representing previous block unique hash.

        Attrib:
            index (int): Block number.
            timestamp (int): Block creation timestamp.
            data (str): Data to be sent.
            previous_hash(str): String representing previous block unique hash.
            hash(str): Current block unique hash.

        """
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.prover = prover
        self.hash = self.hash_block()

    def hash_block(self):
        """Creates the unique hash for the block. It uses sha256."""
        sha = hasher.sha256()
        sha.update((str(self.index) + str(self.timestamp) + str(self.data) + str(self.previous_hash) + str(self.prover)).encode('utf-8'))
        return sha.hexdigest()

def create_genesis_block():
    """To create each block, it needs the hash of the previous one. First
    block has no previous, so it must be created manually (with index zero
     and arbitrary previous hash)"""
    block = Block(0, time.time(),
        {"proof-of-work": 9,"transactions": None},
         "0", "0")

    return block

def proof_of_work(last_hash, b_len, prover, allspeed, target, incrementor = 0):
    import time
    import hashlib as hasher
    # Create a variable that we will use to find our next proof of work
    if incrementor == 0:
        incrementor = random.randrange(0, 500000000)
    i = 0
    found = False
    start_time = time.time()
    timefound = 0
    time_printed = False
    bhash = str(last_hash)

    while not found:
        incrementor += 1
        i += 1
        sha = hasher.sha256()
        sha.update( (bhash + str(incrementor)).encode('utf-8'))
        digest = str(sha.hexdigest())

        if timefound != int(time.time()-start_time):
            timefound = int(time.time()-start_time)
            time_printed = False

        if (time_printed == False and timefound != 0 and timefound % 29 == 0):
            #print('speed - '+str(int(i/timefound)/1000)+' KH\s' + ', blockchain\'s length is ' + str(b_len) +'\n')
            time_printed = True
            allspeed.value += i/timefound


        if (digest[:len(target)] == target):
            found = True
            print('\n' + digest + ' - ' +str(i) +' FOUND!!!')
            timefound = int((time.time()-start_time))
            prover.value = incrementor
            return
        if (int(i%50000)==0):
            if prover.value != 0:
                return

def mine(blockchain,node_pending_transactions, workersnumber = 1):
    global BLOCKCHAIN
    global NODE_PENDING_TRANSACTIONS

    NODE_PENDING_TRANSACTIONS = node_pending_transactions

    while True:
        """Mining is the only way that new coins can be created.
        In order to prevent too many coins to be created, the process
        is slowed down by a proof of work algorithm.
        """
        # Get the last proof of work
        last_block = 0
        with mutex:
            last_hash = BLOCKCHAIN[-1].hash
            b_len = len(BLOCKCHAIN)
            last_block = BLOCKCHAIN[-1]

        print('starting a new search round\n')

        workers = []
        new_blockchain = False
        foundedprover = Value('d', 0)
        allspeed = Value('f', 0)
        start_time = time.time()
        timefound = 0
        time_printed = False
        seed = random.randrange(0, 500000000)
        for i in range(workersnumber):
            seed += 500000000
            p = Process(target = proof_of_work, args = (last_hash,b_len,foundedprover,allspeed,TARGET,seed))
            p.start()
            workers.append(p)

        while True:
            time.sleep(0.25)

            if timefound != int(time.time()-start_time):
                timefound = int(time.time()-start_time)
                time_printed = False

            if (time_printed == False and timefound != 0 and timefound % 30 == 0):
                print('cumulative speed - '+str(int(allspeed.value)/1000)+' KH\s' + ', blockchain\'s length is ' + str(b_len) +'\n')
                time_printed = True
                allspeed.value = 0

            if foundedprover.value != 0:
                for p in workers:
                    p.join()
                break
            # If any other node got the proof, stop searching
            new_blockchain = consensus()
            if new_blockchain != False:
                foundedprover.value = 0.1
                for p in workers:
                    p.join()
                break

        if new_blockchain != False:
            # Update blockchain and save it to file
            with mutex:
                BLOCKCHAIN = new_blockchain
        else:
            # Once we find a valid proof of work, we know we can mine a block so
            # we reward the miner by adding a transaction
            with mutex:
                #Then we add the mining reward
                NODE_PENDING_TRANSACTIONS.append(
                { "from": "network",
                  "to": MINER_ADDRESS,
                  "amount": 1 }
                )

                NODE_PENDING_TRANSACTIONS = validate_transactions(list(NODE_PENDING_TRANSACTIONS))

                # Now we can gather the data needed to create the new block
                new_block_data = {
                "proof-of-work": int(foundedprover.value),
                "transactions": NODE_PENDING_TRANSACTIONS
                }
                new_block_index = int(last_block.index) + 1
                new_block_timestamp = time.time()
                last_block_hash = last_block.hash
                # Empty transaction list
                NODE_PENDING_TRANSACTIONS = []
                # Now create the new block
                mined_block = Block(new_block_index, new_block_timestamp, new_block_data, last_block_hash, int(foundedprover.value))
                BLOCKCHAIN.append(mined_block)

            # Let the client know this node mined a block
            print(str({
              "index": new_block_index,
              "timestamp": str(new_block_timestamp),
              "data": new_block_data,
              "hash": last_block_hash
            }) + "\n")
            print("length is " + str(len(BLOCKCHAIN)))

def find_new_chains():
    global BLOCKCHAIN
    global PEER_NODES
    # Get the blockchains of every other node
    longest_chain_ip  = (MINER_IP, MINER_PORT)
    longest_chain_len = 0
    updated = False
    with mutex:
        longest_chain = BLOCKCHAIN
        longest_chain_len = len(BLOCKCHAIN)

    peerlist = []

    for node_url in PEER_NODES:
        #print('!! '+str(node_url[0]))
        if node_url[0] == MINER_IP and node_url[1] == MINER_PORT:
            continue
        # Get their chains using a GET request
        try:
            chain = None
            alien_chain_len = 0
            with eventlet.Timeout(5, False):
                try:
                    alien_chain_len = int(request(node_url, 'length'))
                except:
                    alien_chain_len = 0

            # Verify other node block is correct
            if alien_chain_len > longest_chain_len:
                longest_chain_len = alien_chain_len
                longest_chain_ip  = node_url

        except Exception:
            #print('Connection to '+node_url+' failed')
            pass

    if longest_chain_ip[0] != MINER_IP or longest_chain_ip[1] != MINER_PORT:
        longest_chain = request(longest_chain_ip, 'chain')
        updated = True

    if updated:
        return longest_chain
    else:
        return None

def consensus():
    # Get the blocks from other nodes
    global BLOCKCHAIN
    longest_chain = find_new_chains()
    if not longest_chain:
        return False
    # If our chain isn't longest, then we store the longest chain
    print('I seems that an external chain is longer')
    print("I'm going to validate it")
    validated = validate_blockchain(longest_chain, BLOCKCHAIN)
    print('VALIDATED: '+str(validated))
    if validated:
        # Give up searching proof, update chain and start over again
        with mutex:
            BLOCKCHAIN = longest_chain
        print('external blockchain passed validation\n')
        return BLOCKCHAIN
    else:
        print('external blockchain did not pass validation\n')
        return False

def validate_blockchain(alien_chain, my_chain):

    index = 0

    if len(my_chain) > 1 and alien_chain[len(my_chain)-1].hash == my_chain[-1].hash:
        index = len(my_chain)
    else:
        index = 0
        open('ledger.txt', 'w').close()

    if not os.path.isfile('ledger.txt'):
        open('ledger.txt','a').close()
        index = 0

    length_of_chain = len(alien_chain)

    while(index < length_of_chain):
        if index == 0:
            index += 1
            continue
        # 1st - verification integrity
        sha = hasher.sha256()
        sha.update( (str(alien_chain[index].previous_hash) + str(alien_chain[index].prover)).encode('utf-8'))
        digest = str(sha.hexdigest())
        if (digest[:len(TARGET)] != TARGET):
            print('digest does not match')
            return False
        # 2st - verification of double spending
        transactions = alien_chain[index].data
        if len(validate_transactions(transactions["transactions"])) != len(transactions["transactions"]):
            return False

        index += 1

    return True

def validate_transactions(transactions):

    network_checked = False
    valid_transactions = []

    for transaction in transactions:
        flawed = False
        f = open('ledger.txt')
        filedata = []
        for line in f:
            if line != '\n':
                filedata.append(line)
        f.close()
        # Checking of the network reward
        if transaction['from'] == 'network' and float(transaction['amount']) == 1:
            if network_checked:
                print('FLAWED!!! ' +str(transaction['from']) + ' ' + transaction['to'] + ' ' + transaction['amount'] )
                print('network is trying to pay off more coins than it is normally set up\n')
                flawed = True
                continue
            network_checked = True

        # Checking of the users spending amounts
        transaction_from_found = False
        counter = 0
        length_of_filedata = len(filedata)

        if transaction['from'] != 'network':
            while counter < length_of_filedata and not flawed:
                data = filedata[counter].split(':')
                if data[0] == transaction['from']:
                    transaction_from_found = True
                    if float(data[1]) < float(transaction['amount']):
                        print('FLAWED!!! ' +str(transaction['from']) + ' ' + transaction['to'] + ' ' + transaction['amount'] )
                        print('transferred amount is more than expected')
                        flawed = True
                        break
                    amount = float(data[1])
                    amount -= float(transaction['amount'])
                    data[1] = amount
                    filedata[counter] = str(data[0]) + ':' +str(float(data[1]))
                counter += 1
            if not transaction_from_found:
                print('address has not been found')
                flawed = True
                continue

        if flawed:
            continue
        # Checking of the users income amounts
        transaction_to_found = False
        counter = 0
        length_of_filedata = len(filedata)

        if length_of_filedata > 0:
            while counter < length_of_filedata:
                data = filedata[counter].split(':')
                if transaction['to'] == data[0]:
                    transaction_to_found = True
                    amount = float(data[1])
                    amount += float(transaction['amount'])
                    data[1] = amount
                    filedata[counter] = str(data[0]) + ':' +str(float(data[1]))
                counter += 1

        if transaction_to_found == False:
            filedata.append(str(transaction['to'])+':'+str(float(transaction['amount'])))

        f = open('ledger.txt', 'w')
        line_counter = 0
        length_of_filedata = len(filedata)

        for line in filedata:
            if line != '\n':
                if line[-1] != '\n':
                    f.write(line + '\n')
                else:
                    f.write(line)

        f.close()

        valid_transactions.append(transaction)

    return valid_transactions

def listen():
    global PEER_NODES
    lSocket = socket.socket()
    lSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lSocket.bind((MINER_IP, MINER_PORT))
    lSocket.listen(5)

    while True:
        conn, addr = lSocket.accept()
        conn.setblocking(0)
        data = b''
        while True:
            try:
                packet = conn.recv(1024)
                if not packet:
                    break
                data += packet
            except socket.error as e:
                break
        if not data:
            conn.close()
            continue
        else:
            data = loads(data.decode())

        if data[0] == 'chain':
            conn.send(dumps(getchain()).encode())
        elif data[0] == 'length':
            blen = 0
            with mutex:
                blen = len(BLOCKCHAIN)
            conn.send(str(blen).encode())
        elif data[0] == 'txion':
            conn.send(str(getnewtransaction(data[1])).encode())
        elif data[0] == 'balance':
            conn.send(str(getbalance(data[1])).encode())
        elif data[0] == 'pendingtxion':
            conn.send(dumps(getpendingtransactions()).encode())
        elif data[0] == 'peernodes':
            conn.send(dumps(PEER_NODES).encode())
            if (data[1][0], data[1][1]) not in PEER_NODES:
                PEER_NODES.append( [ data[1][0], data[1][1]] )

        conn.close()

def request(url, option, payload = None):
    if option is None or option == '':
        return None

    try:
        qSocket = socket.socket()
        qSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        qSocket.settimeout(2)
        qSocket.connect((url[0],url[1]))
        qSocket.send(dumps((option, payload)).encode())
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
            return None

        qSocket.close()
        return data

    except:
        #print('Connection to '+str(url[0])+':'+str(url[1]) + ' failed.')
        pass

def getchain():
    global BLOCKCHAIN
    chain_to_send = []
    with mutex:
        chain_to_send = BLOCKCHAIN
    return chain_to_send

def getbalance(wallet):
    f = open('ledger.txt')
    filedata = []
    for line in f:
        if line != '\n':
            filedata.append(line)
    f.close()
    wallet_found = False
    for line in filedata:
        data = line.split(':')
        if data[0] == wallet:
            wallet_found = True
            return data[1]
    if wallet_found == False:
        return '0'

def getnewtransaction(new_txion):
    global NODE_PENDING_TRANSACTIONS
    if validate_signature(new_txion['from'],new_txion['signature'],new_txion['message']):
        with mutex:
            NODE_PENDING_TRANSACTIONS.append(new_txion)
        # Because the transaction was successfully
        # submitted, we log it to our console
        print("New transaction")
        print("FROM: {0}".format(new_txion['from']))
        print("TO: {0}".format(new_txion['to']))
        print("AMOUNT: {0}\n".format(new_txion['amount']))
        # Then we let the client know it worked out
        return "Transaction submission successful"
    else:
        return "Transaction submission failed. Wrong signature"

def getpendingtransactions():
    txs = []
    with mutex:
        txs = NODE_PENDING_TRANSACTIONS
    return txs

def updatepeernodes():
    open('PEER_NODES.txt', 'w').close()
    global PEER_NODES
    while True:
        peerlist = []
        for node_url in PEER_NODES:
            data = request(node_url, 'peernodes', (MINER_IP, MINER_PORT))
            if data:
                peerlist = data
            if peerlist:
                with mutex:
                    PEER_NODES = PEER_NODES + peerlist
                    output = []
                    for item in PEER_NODES:
                        if item not in output:
                            output.append(item)
                    PEER_NODES = output
        f = open('PEER_NODES.txt', 'w')
        f.write(str(PEER_NODES))
        f.close()
        time.sleep(15)

def validate_signature(public_key,signature,message):
    """Verify if the signature is correct. This is used to prove if
    it's you (and not someon else) trying to do a transaction with your
    address. Called when a user try to submit a new transaction.
    """
    public_key = (base64.b64decode(public_key)).hex()
    signature = base64.b64decode(signature)
    vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(public_key), curve=ecdsa.SECP256k1)
    try:
        return(vk.verify(signature, message.encode()))
    except:
        return False

def welcome_msg():
    print("""       =========================================\n
        SIMPLE COIN v2.0.0 - BLOCKCHAIN SYSTEM\n
       =========================================\n\n
        You can find more help at: https://github.com/Scotchmann/SimpleCoin\n
        (Initial project you can find at https://github.com/cosme12/SimpleCoin)\n
        Make sure you are using the latest version or you may end in
        a parallel chain.\n\n\n""")
    print('Miner has been started at '+str(MINER_IP)+':'+str(MINER_PORT)+' host! Good luck!\n')

def initialize_miner(args):
    global MINER_IP, MINER_PORT, BLOCKCHAIN, PEER_NODES, WORKERSNUMBER
    open('ledger.txt', 'w').close()
    BLOCKCHAIN.append(create_genesis_block())
    error = False
    if MINER_IP == '':
        MINER_IP = socket.gethostbyname(socket.getfqdn())
    if MINER_PORT == 0:
        MINER_PORT = 5000
    if len (args) > 1:

        i = 0
        for item in args:
            if item == '-pn' or item == '--processes':
                try:
                    WORKERSNUMBER = int(args[(i+1)])
                except:
                    print('Argument "workersnumber" is not specified correctly')
                    error = True
            elif item == '-rn' or item == '--remotenode':
                try:
                    node = str(args[i+1]).split(':')
                    PEER_NODES.append([node[0],int(node[1])])
                except:
                    print('Argument "node" is not specified correctly')
                    error = True
            elif item == '-lh' or item == '--localhost':
                try:
                    node = str(args[i+1]).split(':')
                    MINER_IP = node[0]
                    MINER_PORT = int(node[1])
                except:
                    print('Argument "host" is not specified correctly')
                    error = True
            i += 1
    return error

if __name__ == '__main__':
    error = initialize_miner(sys.argv)
    if error:
        exit()

    freeze_support()
    welcome_msg()
    #Start mining
    print('length of BLOCKCHAIN: '+ str(len(BLOCKCHAIN)))

    p1 = Thread(target = mine, args=(BLOCKCHAIN,NODE_PENDING_TRANSACTIONS, WORKERSNUMBER))
    p1.start()

    #Start server to recieve transactions
    p2 = Thread(target = listen)
    p2.start()

    p3 = Thread(target = updatepeernodes)
    p3.start()

    p1.join()
    p2.join()
    p3.join()
