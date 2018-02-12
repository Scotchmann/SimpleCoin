"""Configure this file before you start mining. Check wallet.py for
more details.
"""

# Write your generated adress here. All coins mined will go to this address
#MINER_ADDRESS = "i7YqTeslTO9fMpPYTOrh8p52T21jxpZBf/RiVAS1QRnCel31hpzEfa1T29UWvWlEbzeReIzHG43TxkAnlw5w=="
MINER_ADDRESS = "i7YqTe+slTO9f+MpPYTOrh8p52T21jxpZBf/RiVAS1QRnCel31hpzEfa1T29UWvWlEbzeReIzHG43TxkAnlw5w=="

#MINER_IP = "10.10.10.100"
MINER_IP = "10.10.10.81"
#MINER_IP = "192.168.1.4"
#MINER_IP = "localhost"

MINER_PORT = 5000
#MINER_PORT = 5001

# Write your node url or ip. If you are running it localhost use default
MINER_NODE_URL = "http://"+MINER_IP+":"+str(MINER_PORT)
#MINER_NODE_URL = "http://localhost:5000"
#MINER_NODE_URL = "http://10.10.10.81:5000"
# Store the url data of every other node in the network
# so that we can communicate with them
#PEER_NODES = ["http://10.10.10.100:5000"]
#PEER_NODES = ["http://10.10.10.81:5000"]
PEER_NODES = ["http://10.10.10.81:5001"]
#PEER_NODES = ["http://192.168.1.4:5001"]
#PEER_NODES = ["http://localhost:5001"]
#PEER_NODES = []
