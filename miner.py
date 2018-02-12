#!/usr/bin/env python3
import time
import hashlib as hasher
import json
import requests
import base64
from flask import Flask
from flask import request
from flask import g
from flask import current_app
from multiprocessing import Process, Pipe
import ecdsa
import random
import eventlet
import os.path

import logging
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

from miner_config import MINER_IP, MINER_PORT, MINER_ADDRESS, MINER_NODE_URL, PEER_NODES

node = Flask(__name__)

target = '000000'


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

    block = {
        "index": str(block.index),
        "timestamp": str(block.timestamp),
        "data": str(block.data),
        "hash": block.hash,
        "previous_hash": 0,
        "prover": block.prover
    }

    return block

# Node's blockchain copy
BLOCKCHAIN = []

""" Store the transactions that this node has, in a list
If the node you sent the transaction adds a block
it will get accepted, but there is a chance it gets
discarded and your transaction goes back as if it was never
processed"""
NODE_PENDING_TRANSACTIONS = []

def proof_of_work(last_proof,blockchain):
  # Create a variable that we will use to find our next proof of work
  incrementor = random.randrange(0, 500000000)
  i = 0
  found = False
  start_time = time.time()
  timefound = 0
  time_printed = False
  # Keep incrementing the incrementor until it's equal to a number divisible by 9
  # and the proof of work of the previous block in the chain
  #while not (incrementor % 7919 == 0 and incrementor % last_proof == 0):
  while not found:
    incrementor += 1
    i += 1
    sha = hasher.sha256()
    sha.update( (str(blockchain[-1]['hash']) + str(incrementor)).encode('utf-8'))
    digest = str(sha.hexdigest())


    if (timefound != int((time.time()-start_time))):
        timefound = int((time.time()-start_time))
        time_printed = False

    if (time_printed == False and timefound != 0 and timefound % 60 == 0):
        print('speed - '+str(int(i/timefound)/1000)+' KH\s' + ', blockchain\'s length is ' + str(len(blockchain)) +'\n')
        time_printed = True

    if (digest[:len(target)] == target):
        found = True
        print("")
        print(digest + ' - ' +str(i) +' FOUND!!!')
        timefound = int((time.time()-start_time))

    # Check if any node found the solution every 60 seconds
    if (int(i%200000)==0):
        # If any other node got the proof, stop searching
        new_blockchain = consensus(blockchain)
        if new_blockchain != False:
            #(False:another node got proof first, new blockchain)
            return (False,new_blockchain)
  # Once that number is found, we can return it as a proof of our work
  return (incrementor,blockchain)

def mine(a,blockchain,node_pending_transactions):
    BLOCKCHAIN = blockchain
    NODE_PENDING_TRANSACTIONS = node_pending_transactions
    while True:
        """Mining is the only way that new coins can be created.
        In order to prevent to many coins to be created, the process
        is slowed down by a proof of work algorithm.
        """
        # Get the last proof of work

        last_block = BLOCKCHAIN[-1]
        try:
            last_proof = last_block.data['proof-of-work']
        except Exception:
            last_proof = 0

        print('starting a new search round\n')
        # Find the proof of work for the current block being mined
        # Note: The program will hang here until a new proof of work is found
        proof = proof_of_work(last_proof, BLOCKCHAIN)
        # If we didn't guess the proof, start mining again
        if proof[0] == False:
            # Update blockchain and save it to file
            BLOCKCHAIN = proof[1]
            i = 0
            for item in BLOCKCHAIN:
                package = []
                package.append('chunk')
                package.append(item)
                package.append(i)
                a.send(package)
                requests.get(MINER_NODE_URL + "/blocks?update=" + 'syncing'+str(i))
                while(a.recv() != i):
                    wait = True

                i += 1

            sha = hasher.sha256()
            sha.update( str(json.dumps(BLOCKCHAIN)).encode('utf-8') )
            digest = str(sha.hexdigest())
            package = []
            package.append('digest')
            package.append(digest)
            a.send(package)
            requests.get(MINER_NODE_URL + "/blocks?update=" + 'syncing_digest')
            print('synced with an external chain\n')
            continue
        else:
            # Once we find a valid proof of work, we know we can mine a block so
            # we reward the miner by adding a transaction
            #First we load all pending transactions sent to the node server
            data = None
            with eventlet.Timeout(5, False):
                url     = MINER_NODE_URL + "/txion?update=" + MINER_ADDRESS
                payload = {"source": "miner", "option":"pendingtxs", "address": MINER_ADDRESS}
                headers = {"Content-Type": "application/json"}

                data = requests.post(url, json=payload, headers=headers).text

            if data is not None:
                NODE_PENDING_TRANSACTIONS = json.loads(data)
            else:
                print('local request failed')
                continue

            # #Then we add the mining reward
            NODE_PENDING_TRANSACTIONS.append(
            { "from": "network",
              "to": MINER_ADDRESS,
              "amount": 1 }
            )

            NODE_PENDING_TRANSACTIONS = validate_transactions(list(NODE_PENDING_TRANSACTIONS))

            # Now we can gather the data needed to create the new block
            new_block_data = {
            "proof-of-work": proof[0],
            "transactions": NODE_PENDING_TRANSACTIONS
            }
            new_block_index = int(last_block['index']) + 1
            new_block_timestamp = time.time()
            last_block_hash = last_block['hash']
            # Empty transaction list
            NODE_PENDING_TRANSACTIONS = []
            # Now create the new block
            mined_block = Block(new_block_index, new_block_timestamp, new_block_data, last_block_hash, proof[0])
            #BLOCKCHAIN.append(mined_block)
            block_to_add = {
                "index": str(mined_block.index),
                "timestamp": str(mined_block.timestamp),
                "data": str(mined_block.data),
                "hash": mined_block.hash,
                "previous_hash": mined_block.previous_hash,
                "prover": mined_block.prover
            }
            BLOCKCHAIN.append(block_to_add)
            # Let the client know this node mined a block
            print(json.dumps({
              "index": new_block_index,
              "timestamp": str(new_block_timestamp),
              "data": new_block_data,
              "hash": last_block_hash
            }) + "\n")

            with eventlet.Timeout(5,False):
                i = 0
                for item in BLOCKCHAIN:
                    package = []
                    package.append('chunk')
                    package.append(item)
                    package.append(i)
                    a.send(package)
                    requests.get(MINER_NODE_URL + "/blocks?update=" + "internal_syncing")
                    while(a.recv() != i):
                        wait = True

                    i += 1

                sha = hasher.sha256()
                sha.update( str(json.dumps(BLOCKCHAIN)).encode('utf-8') )
                digest = str(sha.hexdigest())
                package = []
                package.append('digest')
                package.append(digest)
                a.send(package)
                requests.get(MINER_NODE_URL + "/blocks?update=" + "internal_syncing")

def find_new_chains(blockchain):
    # Get the blockchains of every other node
    longest_chain = blockchain
    for node_url in PEER_NODES:
        # Get their chains using a GET request
        try:
            chain = None
            with eventlet.Timeout(5, False):
                chain = requests.get(node_url + "/blocks").content
            if chain is not None:
                # Convert the JSON object to a Python dictionary
                chain = json.loads(chain)
            else:
                print('Request to '+node_url+' has exceeded it\'s timeout.')
                continue

            # Verify other node block is correct
            if len(chain) > len(longest_chain):
                longest_chain = chain

        except Exception:
            print('Connection to '+node_url+' failed')
    return longest_chain

def consensus(blockchain):
    # Get the blocks from other nodes
    longest_chain = find_new_chains(blockchain)
    # If our chain isn't longest, then we store the longest chain
    BLOCKCHAIN = blockchain

    # If the longest chain wasn't ours, then we set our chain to the longest
    if longest_chain == BLOCKCHAIN:
        # Keep searching for proof
        return False

    validated = validate_blockchain(longest_chain, blockchain)
    print('VALIDATED: '+str(validated))
    if validated:
        # Give up searching proof, update chain and start over again
        BLOCKCHAIN = longest_chain
        print('external blockcain passed validation\n')
        return BLOCKCHAIN
    else:
        print('external blockcain did not pass validation\n')
        return False

def validate_blockchain(chain, blockchain):

    index = 0

    if len(blockchain) > 1 and chain[len(blockchain)-1]['hash'] == blockchain[-1]['hash']:
        index = len(blockchain)
    else:
        index = 0
        open('ledger.txt', 'w').close()

    if not os.path.isfile('ledger.txt'):
        open('ledger.txt','a').close()
        index = 0

    length_of_chain = len(chain)

    while(index < length_of_chain):
        if index == 0:
            index += 1
            continue
        # 1st - verification integrity
        sha = hasher.sha256()
        sha.update( (str(chain[index]['previous_hash']) + str(chain[index]['prover'])).encode('utf-8'))
        digest = str(sha.hexdigest())
        if (digest[:len(target)] != target):
            print('digest does not match')
            return False
        # 2st - verification of double spending
        #transactions = (chain[index]["data"]).replace("'", '"')
        transactions = json.loads((chain[index]["data"]).replace("'", '"'))

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
            filedata.append(str(transaction['to'])+':'+str(transaction['amount']))

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

@node.route('/blocks', methods=['GET','POST'])
def get_blocks():
    # Load current blockchain. Only you, should update your blockchain
    if request.args.get("update") == 'internal_syncing' or (str(request.args.get("update")))[:7] == 'syncing':
        global BLOCKCHAIN
        global received_blockchain
        with eventlet.Timeout(5, False):
            data = b.recv()
        if data is not None:
            if data[0] == 'chunk':
                if data[2] == 0:
                    received_blockchain = []
                received_blockchain.append(data[1])
                b.send(data[2])
            elif data[0] == 'digest':
                sha = hasher.sha256()
                sha.update( str(json.dumps(received_blockchain)).encode('utf-8') )
                digest = str(sha.hexdigest())
                if digest == data[1]:
                    BLOCKCHAIN = received_blockchain
                else:
                    print('Received blockchain is corrupted.')
        else:
            print('Couldn\'t get data from pipe')
        chain_to_send = BLOCKCHAIN
    else:
        # Any other node trying to connect to your node will use this
        chain_to_send = BLOCKCHAIN
    # Convert our blocks into dictionaries so we can send them as json objects later
    chain_to_send_json = []
    for block in chain_to_send:
        block = {
            "index": str(block['index']),
            "timestamp": str(block['timestamp']),
            "data": str(block['data']),
            "hash": block['hash'],
            "previous_hash": block['previous_hash'],
            "prover": block['prover']
        }
        chain_to_send_json.append(block)

    # Send our chain to whomever requested it
    chain_to_send = json.dumps(chain_to_send_json)
    return chain_to_send

@node.route('/txion', methods=['GET','POST'])
def transaction():
    """Each transaction sent to this node gets validated and submitted.
    Then it waits to be added to the blockchain. Transactions only move
    coins, they don't create it.
    """
    if request.method == 'POST':
        # On each new POST request, we extract the transaction data
        new_txion = request.get_json()
        if new_txion['source'] == "wallet" and new_txion['option'] == "newtx":
            # Then we add the transaction to our list
            if validate_signature(new_txion['from'],new_txion['signature'],new_txion['message']):
                NODE_PENDING_TRANSACTIONS.append(new_txion)
                # Because the transaction was successfully
                # submitted, we log it to our console
                print("New transaction")
                print("FROM: {0}".format(new_txion['from']))
                print("TO: {0}".format(new_txion['to']))
                print("AMOUNT: {0}\n".format(new_txion['amount']))
                # Then we let the client know it worked out
                return "Transaction submission successful\n"
            else:
                return "Transaction submission failed. Wrong signature\n"

        elif new_txion['source'] == "wallet" and new_txion['option'] == "balance":
             f = open('ledger.txt')
             filedata = []
             for line in f:
                 if line != '\n':
                     filedata.append(line)
             f.close()
             wallet_found = False
             for line in filedata:
                 data = line.split(':')
                 if data[0] == new_txion['wallet']:
                     wallet_found = True
                     return data[1]
             if wallet_found == False:
                 return "0"


        #Send pending transactions to the mining process
        elif new_txion['source'] == "miner" and new_txion["option"] == "pendingtxs":

            pending = json.dumps(NODE_PENDING_TRANSACTIONS)
            # Empty transaction list
            NODE_PENDING_TRANSACTIONS[:] = []
            return pending
        else:
            return 'Arguments not specified'

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
        SIMPLE COIN v1.0.0 - BLOCKCHAIN SYSTEM\n
       =========================================\n\n
        You can find more help at: https://github.com/Scotchmann/SimpleCoin\n
        Make sure you are using the latest version or you may end in
        a parallel chain.\n\n\n""")
    print('Miner has been started at '+MINER_NODE_URL+'! Good luck!\n')

def initialize_miner():
    result = consensus()

if __name__ == '__main__':
    welcome_msg()
    #Start mining
    b,a=Pipe(duplex=True)
    answer = consensus(BLOCKCHAIN)

    if answer != False:
        BLOCKCHAIN = answer
        print('blockchain has been initialized with an external chain\n')
    else:
        BLOCKCHAIN.append(create_genesis_block())

    p1 = Process(target = mine, args=(a,BLOCKCHAIN,NODE_PENDING_TRANSACTIONS))
    p1.start()
    #Start server to recieve transactions
    p2 = Process(target = node.run(host = MINER_IP, port = MINER_PORT), args=b)

    p2.start()
