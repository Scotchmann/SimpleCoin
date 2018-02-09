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
        "prover": block.prover
    }

    return block




# Node's blockchain copy
BLOCKCHAIN = []
BLOCKCHAIN.append(create_genesis_block())

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
  sha = hasher.sha256()
  start_time = time.time()
  timefound = 0
  time_printed = False
  # Keep incrementing the incrementor until it's equal to a number divisible by 9
  # and the proof of work of the previous block in the chain
  #while not (incrementor % 7919 == 0 and incrementor % last_proof == 0):
  while not found:
    incrementor += 1
    i += 1
    blockchain[-1]['hash']
    sha.update( (str(blockchain[-1]['hash']) + str(incrementor)).encode('utf-8'))
    digest = str(sha.hexdigest())


    if (timefound != int((time.time()-start_time))):
        timefound = int((time.time()-start_time))
        time_printed = False

    if (time_printed == False and timefound != 0 and timefound % 60 == 0):
        print ('speed - '+str(int(i/timefound)/1000)+' KH\s')
        time_printed = True

    if (digest[:len(target)] == target):
        found = True
        print("")
        print (digest + ' - ' +str(i) +' FOUND!!!')
        timefound = int((time.time()-start_time))

    # Check if any node found the solution every 60 seconds
    if (int(i%800000)==0):
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

        last_block = BLOCKCHAIN[len(BLOCKCHAIN) - 1]
        try:
            last_proof = last_block.data['proof-of-work']
        except Exception:
            last_proof = 0
        # Find the proof of work for the current block being mined
        # Note: The program will hang here until a new proof of work is found
        proof = proof_of_work(last_proof, BLOCKCHAIN)
        # If we didn't guess the proof, start mining again
        if proof[0] == False:
            # Update blockchain and save it to file
            BLOCKCHAIN = proof[1]
            a.send(BLOCKCHAIN)
            requests.get(MINER_NODE_URL + "/blocks?update=" + MINER_ADDRESS)
            continue
        else:
            # Once we find a valid proof of work, we know we can mine a block so
            # we reward the miner by adding a transaction
            #First we load all pending transactions sent to the node server
            data = None
            with eventlet.Timeout(5, False):
                data = requests.get(MINER_NODE_URL + "/txion?update=" + MINER_ADDRESS).content
            if data != None:
                NODE_PENDING_TRANSACTIONS = data
            else:
                print('local request failed')
                continue

            NODE_PENDING_TRANSACTIONS = json.loads(NODE_PENDING_TRANSACTIONS)
            # #Then we add the mining reward
            NODE_PENDING_TRANSACTIONS.append(
            { "from": "network",
              "to": MINER_ADDRESS,
              "amount": 1 }
            )
            # Now we can gather the data needed to create the new block
            new_block_data = {
            "proof-of-work": proof[0],
            "transactions": list(NODE_PENDING_TRANSACTIONS)
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
            a.send(BLOCKCHAIN)
            requests.get(MINER_NODE_URL + "/blocks?update=" + MINER_ADDRESS)

def find_new_chains():
    # Get the blockchains of every other node
    other_chains = []
    for node_url in PEER_NODES:
        # Get their chains using a GET request
        try:
            block = None
            with eventlet.Timeout(5, False):
                block = requests.get(node_url + "/blocks").content
            if block is not None:
                # Convert the JSON object to a Python dictionary
                block = json.loads(block)
            else:
                print('Request to '+node_url+' has exceeded it\'s timeout.')
                continue

            # Verify other node block is correct
            validated = validate_blockchain(block)
            if validated == True:
                # Add it to our list
                other_chains.append(block)
        except Exception:
            print('Connection to '+node_url+' failed')
    return other_chains

def consensus(blockchain):
    # Get the blocks from other nodes
    other_chains = find_new_chains()
    # If our chain isn't longest, then we store the longest chain
    BLOCKCHAIN = blockchain
    longest_chain = BLOCKCHAIN
    for chain in other_chains:
        if len(longest_chain) < len(chain):
            longest_chain = chain
    # If the longest chain wasn't ours, then we set our chain to the longest
    if longest_chain == BLOCKCHAIN:
        # Keep searching for proof
        return False
    else:
        # Give up searching proof, update chain and start over again
        BLOCKCHAIN = longest_chain
        return BLOCKCHAIN

def validate_blockchain(block):
    """Validate the submited chain. If hashes are not correct, return false
    block(str): json
    """
    return True

def validate_transactions(transactions):
    for transaction in transactions:
        print(transaction)
    return True

@node.route('/blocks', methods=['GET'])
def get_blocks():
    # Load current blockchain. Only you, should update your blockchain
    if request.args.get("update") == MINER_ADDRESS:
        global BLOCKCHAIN
        BLOCKCHAIN = b.recv()
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
        # Then we add the transaction to our list
        if validate_signature(new_txion['from'],new_txion['signature'],new_txion['message']):
            f = open('NODE_PENDING_TRANSACTIONS.txt', 'w')
            f.write(new_txion['from'] + ' ' + new_txion['to'] + ' ' + new_txion['amount'])
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
    #Send pending transactions to the mining process
    elif request.method == 'GET' and request.args.get("update") == MINER_ADDRESS:
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

def initialize_miner():
    result = consensus()

if __name__ == '__main__':
    welcome_msg()
    #Start mining
    a,b=Pipe()
    p1 = Process(target = mine, args=(a,BLOCKCHAIN,NODE_PENDING_TRANSACTIONS))
    p1.start()
    #Start server to recieve transactions
    p2 = Process(target = node.run(host = MINER_IP, port = MINER_PORT), args=b)
    p2.start()
