# BlockChainApplication_P5

## Blockchain Application : Event Publisher 
The idea was inspiered by [Eventbrite](https://www.eventbrite.com/)

## Description 

The project concentrates on implementing the Blockchain to publish event information (decentralized property) and using Blockchain to publish upcoming event and keep the history of the events (immutable property) of the Blockchain. Miners will publish the event info after solving hash puzzel into the blockchain to be visible to the peers. 
In case of any change in the event information, miners should publish the new block and maintain the history. 

[GO Resources](https://thenewstack.io/make-a-restful-json-api-go/)


## Functionality
-  Blocks will be produced with detail description of event so Blockchain contains Organizer ID (public key) and the event detail as key value pair.  
-  Miners will publish event detail in the blockchain after solving the hash puzzel.
-  Peers will see the list of events and get updated about upcomming events. 
-  Miners receive transaction fee for block generation.

## Define Success

-  Miners solve hash puzzel for generating the new block.
-  Miners wrap the event information into the blockchain.
-  Each block contains organizer ID, and Event information as key value pair.
-  Peers can see and download event list anytime.
-  Miners receive block generation transaction fee.

## TimeLine 

Markdown | Less | Pretty
--- | --- | ---
*Still* | `renders` | **nicely**
1 | 2 | 3

**Description** | **Expected Date**  | 
--- | --- |
Architecture Design | Apr, 22| 
Data Structure  | Apr, 23| 
Generate Block  | Apr, 24| 
Block being produced with detail description of event so blockchaincontains organizer ID and the Event detail as key value pair | Apr, 25| 
Miner will publish event detail in the blockChain after POW| Apr, 26| 
Peers will see the list of events| Apr, 27| 
Miners receives transaction fee after any block generation | Apr, 28| 
Progress Report | Apr, 29| 
MidPoint Check | May, 1| 
Optimize, debugging  | May, 10 - May, 11| 
Test and Wrap up  | May, 12 - May, 13| 
Progress Report and Demo Preparation | May, 14| 


### Send HeartBeat:
1. Every user would hold a PeerList of up to 32 peer nodes. (32 is the number Ethereum uses.) The PeerList can temporarily hold more than 32 nodes, but before sending HeartBeats, a node will first re-balance the PeerList by choosing the 32 closest peers. "Closest peers" is defined by this: Sort all peers' Id, insert SelfId, consider the list as a cycle, and choose 16 nodes at each side of SelfId. For example, if SelfId is 10, PeerList is [7, 8, 9, 15, 16], then the closest 4 nodes are [8, 9, 15, 16]. HeartBeat is sent to every peer nodes at "/heartbeat/receive". 
2. For each HeartBeat, a node would randomly decide (this will change in Project 4) if it will create a new block. If so, add the block information into HeartBeatData and send the HeartBeatData to others.

### Receive HeartBeat:
1. When a node received a HeartBeat, the node will add the sender’s IP address, along with sender’s PeerList into its own PeerList. At this time, the number of peers stored in PeerList might exceed 32 and it is ok. As described in previously, you don’t have to rebalance every time you receive a HeartBeat. Rebalance happens only before you send HeartBeats.
2. If the HeartBeatData contains a new block, the node will first check if the previous block exists (the previous block is the block whose hash is the parentHash of the next block).
3. If the previous block doesn't exist, the node will ask every peer at "/block/{height}/{hash}" to download that block. 
4. After making sure previous block exists, insert the block from HeartBeatData to the current BlockChain. 
5. Since every node only has 32 peers, every peer will forward the new block to all peers according to its PeerList. That is to make sure every user in the network would receive the new block. For this project. Every HeartBeatData takes 2 hops, which means after a node received a HeartBeatData from the original block maker, the remaining hop times is 1.
You are required to implement those Restful routes. You must not change the route name, route method, request or response.

```linux
/show
Method: GET
Description: Display the PeerList and the BlockChain. Use the helpful function BlockChain.show() in the starter code to display the BlockChain, and add your own function to display the PeerList.

/upload
Method: GET
Response: The JSON string of the BlockChain.
Description: Return JSON string of the entire blockchain to the downloader.

/block/{height}/{hash}
Method: GET
Response: If you have the block, return the JSON string of the specific block; if you don't have the block, return HTTP 204: StatusNoContent; if there's an error, return HTTP 500: InternalServerError. 
Description: Return JSON string of a specific block to the downloader.

/heartbeat/receive
Method: POST
Request: HeartBeatData(see the data structure below)
Description: Receive a heartbeat.

/start
Description: You can start the program by calling this route(be careful to start only once), or start the program during bootstrap.
```
 

You are required to implement those data structures. You can change the name or internal fields, but the JSON format you send to others must remain unchanged.

```linux
HeartBeatData
    ifNewBlock, id(sender's Id), addr(sender's Addr), numberOfHops, blockJson, peerMapJson
PeerList
    selfId, peerMap, maxLength, mux(lock)
RegisterData
    assignedId, peerMapJson
SyncBlockChain
    bc(BlockChain), mux(lock)

Additional functions of P2.BlockChain struct that may be helpful:

GenBlock(), CheckParentHash()
```
Others:

1. To help demonstrate the BlockChain, there's a helpful function Show() that's been added into your starter code. If you cannot see it, please let the TA know. 

Now that we know how to make a new block from project 2, we need to let the world know about this new block. Your software will "listen" on port 6686 to discover other peers and hear about their new blocks. The TA will announce an IP address of the first peer. Your goal is to design your program such that

1) The latest block of your blockchain will reach all the peers online.

2) Your program does not create too much congestion.

For this project, you will develop a Restful API with the starter code (Links to an external site.)Links to an external site. You are required to create your own repository from that link, and push your code there.

[GO Resources](https://thenewstack.io/make-a-restful-json-api-go/)

Here's the workflow of the system:

### Registration:
1. After a new node is launched, it will go to "mc07.cs.usfca.edu:6688/peer" to register itself, and get an Id(nodeId). 
2. Then, the node will go to any peer on its PeerList to download the current BlockChain. 
3. After registration, the node will start to send HeartBeat for every 5~10 seconds.

### Send HeartBeat:
1. Every user would hold a PeerList of up to 32 peer nodes. (32 is the number Ethereum uses.) The PeerList can temporarily hold more than 32 nodes, but before sending HeartBeats, a node will first re-balance the PeerList by choosing the 32 closest peers. "Closest peers" is defined by this: Sort all peers' Id, insert SelfId, consider the list as a cycle, and choose 16 nodes at each side of SelfId. For example, if SelfId is 10, PeerList is [7, 8, 9, 15, 16], then the closest 4 nodes are [8, 9, 15, 16]. HeartBeat is sent to every peer nodes at "/heartbeat/receive". 
2. For each HeartBeat, a node would randomly decide (this will change in Project 4) if it will create a new block. If so, add the block information into HeartBeatData and send the HeartBeatData to others.

### Receive HeartBeat:
1. When a node received a HeartBeat, the node will add the sender’s IP address, along with sender’s PeerList into its own PeerList. At this time, the number of peers stored in PeerList might exceed 32 and it is ok. As described in previously, you don’t have to rebalance every time you receive a HeartBeat. Rebalance happens only before you send HeartBeats.
2. If the HeartBeatData contains a new block, the node will first check if the previous block exists (the previous block is the block whose hash is the parentHash of the next block).
3. If the previous block doesn't exist, the node will ask every peer at "/block/{height}/{hash}" to download that block. 
4. After making sure previous block exists, insert the block from HeartBeatData to the current BlockChain. 
5. Since every node only has 32 peers, every peer will forward the new block to all peers according to its PeerList. That is to make sure every user in the network would receive the new block. For this project. Every HeartBeatData takes 2 hops, which means after a node received a HeartBeatData from the original block maker, the remaining hop times is 1.
You are required to implement those Restful routes. You must not change the route name, route method, request or response.

```linux
/show
Method: GET
Description: Display the PeerList and the BlockChain. Use the helpful function BlockChain.show() in the starter code to display the BlockChain, and add your own function to display the PeerList.

/upload
Method: GET
Response: The JSON string of the BlockChain.
Description: Return JSON string of the entire blockchain to the downloader.

/block/{height}/{hash}
Method: GET
Response: If you have the block, return the JSON string of the specific block; if you don't have the block, return HTTP 204: StatusNoContent; if there's an error, return HTTP 500: InternalServerError. 
Description: Return JSON string of a specific block to the downloader.

/heartbeat/receive
Method: POST
Request: HeartBeatData(see the data structure below)
Description: Receive a heartbeat.

/start
Description: You can start the program by calling this route(be careful to start only once), or start the program during bootstrap.
```
 

You are required to implement those data structures. You can change the name or internal fields, but the JSON format you send to others must remain unchanged.

```linux
HeartBeatData
    ifNewBlock, id(sender's Id), addr(sender's Addr), numberOfHops, blockJson, peerMapJson
PeerList
    selfId, peerMap, maxLength, mux(lock)
RegisterData
    assignedId, peerMapJson
SyncBlockChain
    bc(BlockChain), mux(lock)

Additional functions of P2.BlockChain struct that may be helpful:

GenBlock(), CheckParentHash()
```
Others:

1. To help demonstrate the BlockChain, there's a helpful function Show() that's been added into your starter code. If you cannot see it, please let the TA know. 
