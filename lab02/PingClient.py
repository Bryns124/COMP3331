# Made for comp3331. PingClient.py is specified to send 15 ping requests to a server given in as an arguement.
# By John Dao z5258962

# imports
from socket import *
import sys

host = sys.argv[1]
port = int(sys.argv[2])

