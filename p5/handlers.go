package p5

import (
	"MerklePatriciaTree/p3/cs686-blockchain-p3-RozitaTeymourzadeh/p2"
	"MerklePatriciaTree/p5/Blockchain_Application_P5/data"
	"MerklePatriciaTree/p5/Blockchain_Application_P5/p4"
	"bytes"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/sha3"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

var SBC data.SyncBlockChain
var Peers data.PeerList
var Heart data.HeartBeatData
var ifStarted bool

var TA_SERVER = "http://localhost:6688"
var REGISTER_SERVER = TA_SERVER + "/peer"
var ASK_PEERS = "/block"
var SELF_ADDR = "localhost:6686"
var SELF_ID = 0
var FIRST_PEER = "localhost:6686"
var BC_DOWNLOAD_SERVER = FIRST_PEER + "/upload"
var RECEIVE_PATH = "/heartbeat/receive"
var STOP_GEN_BLOCK = false
var NONCE_ZERO ="00000"


var newTransactionObject data.Transaction
//var mpt p4.MerklePatriciaTrie


var TransactionMap  map[string]data.Transaction
//var userKey *rsa.PrivateKey
var minerKey *rsa.PrivateKey

/* init()
*
* Initialization
*
*/
func init() {

	fmt.Println("......Initialization ....")
	SBC = data.NewBlockChain()
	Peers = data.NewPeerList(Peers.GetSelfId(),32)
	ifStarted = false

	TransactionMap = make(map[string]data.Transaction)
	/*Init Block*/
	mpt := p4.MerklePatriciaTrie{}
	mpt.Initial()
	mpt.Insert(p4.StringRandom(2),p4.StringRandom(5))
	block:=p4.Block{}
	block.Initial(1,"gensis",mpt,NONCE_ZERO)
	block.Header.Nonce = NONCE_ZERO
	SBC.Insert(block)

	if len(os.Args) > 1 {
		responseString := string(os.Args[1])
		fmt.Println(responseString)
		result , err := strconv.ParseInt(responseString,10,32)
		if err != nil {
			panic(err)
		}
		id  := int32(result)
		Peers.Register(id)
		SELF_ADDR="localhost"+os.Args[1]
		Peers.Add(FIRST_PEER,6686)
		publicKey,_:=data.ParseRsaPublicKeyFromPemStr("HARD_CODED_PEER1")
		Peers.AddPublicKey(publicKey,6686)
	} else {
		Peers.Register(6686)
		SELF_ADDR="localhost:6686"
	}
}

/* Start
*
* To start the application
* Register ID, download BlockChain, start HeartBeat
*
*/
func Start(w http.ResponseWriter, r *http.Request) {

	/*Register*/
	if ifStarted == true {
		fmt.Println("Register on TA Server!")
		Register()
	}else{
		fmt.Println("Port Register!" , Peers.GetSelfId())
	}
	fmt.Println("Host is : ", r.Host)
	SELF_ADDR = r.Host
	if r.Host != FIRST_PEER{
		fmt.Println("Not First node: download().")
		Download()
	}else{
		fmt.Println("First node: Skip downloading.")
	}


	/* Start Trying Nonce */
	minerKey = data.GenerateKeyPair(4096)

	fmt.Println("Public Key:", minerKey.PublicKey)
	fmt.Println("Private Key::", minerKey)


	//publicKeyAsPemStr,_:= data.ExportRsaPublicKeyAsPemStr(&userKey.PublicKey)
	//Peers.Add(publicKeyAsPemStr,Peers.GetSelfId())
	Peers.AddPublicKey(&minerKey.PublicKey,Peers.GetSelfId())
	go StartTryingNonce()

	/*Timer to send heartBeat periodically*/
	ticker := time.NewTicker(10 * time.Second)
	quit := make(chan struct{})
	for {
		select {
		case <- ticker.C:
			StartHeartBeat()
		case <- quit:
			ticker.Stop()
			return
		}
	}
}

/* Show
*
* Shows the PeerMap and the BlockChain
*
*/
func Show(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "%s\n %s", Peers.Show(), SBC.Show())
}


/* Canonical
*
* Shows the BlockChain after POW
*
*/
func Canonical(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "%s\n", SBC.Canonical())
}


/* Register
*
* Register to TA's server
* get an ID and register to PeerList
*
*/
func Register() {
	response, err := http.Get(REGISTER_SERVER)
	if err != nil {
		log.Fatal(err)
	}
	defer response.Body.Close()
	responseData, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatal(err)
	}
	responseString := string(responseData)
	fmt.Println(responseString)
	result , err := strconv.ParseInt(responseString,10,32)
	if err != nil {
		panic(err)
	}
	id  := int32(result)
	Peers = data.NewPeerList(id,32)
}


/* Download
*
* Download blockchain from TA server
*
*/
func Download() {
	uploadAddress:="http://" + FIRST_PEER + "/upload"
	fmt.Println("Download from URL:" + uploadAddress)
	peerMapStringValue,_ := Peers.EncodePeerMapToJSON()
	registerData := data.NewRegisterData(Peers.GetSelfId(),peerMapStringValue)
	jsonBytes, err := json.Marshal(registerData)
	req, err := http.NewRequest("POST", uploadAddress, bytes.NewBuffer(jsonBytes))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	response, err := client.Do(req)
	fmt.Println("---> Upload Request from:[", FIRST_PEER ,"] --->")
	if err != nil {
		panic(err)
	}
	defer response.Body.Close()
	fmt.Println("response Status:", response.Status)
	fmt.Println("response Headers:", response.Header)
	fmt.Println("response from peer:",response.Body)
	responseData, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatal(err)
	}
	responseString := string(responseData)
	SBC.UpdateEntireBlockChain(responseString)
}

/* Upload()
*
* Return the BlockChain's JSON for any peer who call this function
*
*/
func Upload(w http.ResponseWriter, r *http.Request) {
	fmt.Println(".....Upload .....")
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}
	log.Println(string(body))
	registerData := data.NewRegisterData(0, "")
	registerData.DecodeFromJSON(string(body))
	fmt.Println("AssignedId:" , registerData.AssignedId)
	fmt.Println("PeerMapJson:" , registerData.PeerMapJson)
	blockChainJSON, err := SBC.BlockChainToJson()
	if err != nil {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
	}
	fmt.Fprint(w, blockChainJSON)
}


/* UploadBlock
*
* Upload a block to whoever called this method, return jsonStr
* Return the Block's JSON
*
*/
func UploadBlock(w http.ResponseWriter, r *http.Request) {
	fmt.Println("<--- UploadBlock Received  From :[", r.Host ,"] <---")
	param := strings.Split(r.URL.Path,"/")
	h, err := strconv.ParseInt(param[2], 10, 32)
	fmt.Println("param0:",param[0])
	fmt.Println("param1:",param[1])
	fmt.Println("param2:",param[2])
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("HTTP 500: InternalServerError. " + err.Error()))
	} else {
		encode := param[3]
		block, flag := SBC.GetBlock(int32(h), encode)
		if flag == false {
			w.WriteHeader(http.StatusNoContent)
		} else {
			blockStr, err := block.EncodeToJSON()
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("HTTP 500: InternalServerError. " + err.Error()))
			} else {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(blockStr))
			}
		}
	}
}

/* HeartBeatReceive
*
* Add the remote address, and the PeerMapJSON into local PeerMap
* Then check if the HeartBeatData contains a new block
*
*/
func HeartBeatReceive(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	data, _ := ioutil.ReadAll(r.Body)
	fmt.Println("<--- HeartBeat Received  From:[", r.Host ,"] <---")
	fmt.Fprintf(w, "%s\n", r.Host)
	fmt.Fprintf(w, "%s", string(data))
	err := json.Unmarshal(data, &Heart)
	if err != nil {
		fmt.Println("FATAL:  Faulty HeartBeatReceive: ", err)
	} else {

	}
	if Heart.Addr ==  SELF_ADDR {
		return
	}
	Peers.AddPublicKey(Heart.PeerPublicKey,Heart.Id)
	Peers.Add(Heart.Addr, Heart.Id)
	Peers.InjectPeerMapJson(Heart.PeerMapJson,  SELF_ADDR)
	//&& Heart.IfValidTransaction
	if Heart.IfNewBlock {
		heartBlock := p4.Block{}
		heartBlock.DecodeFromJSON(Heart.BlockJson)


		// pow
		receivedPuzzle := heartBlock.Header.ParentHash + heartBlock.Header.Nonce + heartBlock.Value.GetRoot()
		sum := sha3.Sum256([]byte(receivedPuzzle))

		if strings.HasPrefix(hex.EncodeToString(sum[:]), NONCE_ZERO){
			fmt.Println("Block with NONCE arrived from:[", r.Host ,"]")
			latestBlocks := SBC.GetLatestBlocks()
			for i:= 0 ; i < len(latestBlocks); i++ {
				if latestBlocks[i].Header.Hash == heartBlock.Header.ParentHash {
					STOP_GEN_BLOCK =true
					break
				}
			}
			if (heartBlock.Header.Height == 1) {
				if Heart.Balance == 0 {

				}else{
					SBC.Insert(heartBlock)
				}
			} else {
				_, flag := SBC.GetBlock(heartBlock.Header.Height-1, heartBlock.Header.ParentHash)
				if flag {
					fmt.Println("No.Gap.Inserting Heart Beat Block:",heartBlock)
					fmt.Println("No.Gap.SBC:",SBC)
					if Heart.Balance == 0 {
					}else {
						SBC.Insert(heartBlock)
					}
				} else {
					fmt.Println("Gap.Inserting Heart Beat Block:",heartBlock)
					fmt.Println("Gap.SBC:",SBC)
					AskForBlock(heartBlock.Header.Height-1, heartBlock.Header.ParentHash)
					if Heart.Balance == 0 {
					}else{
						SBC.Insert(heartBlock)
					}
				}
			}
		}else{
			fmt.Println(" Heart Beat Block does not contain block! unmatch Nonce:", heartBlock.Header.Nonce)
		}
	} else {
		fmt.Println("HeartBeat flag is false! There is no block in heartBeat!")
	}
	Heart.Hops -=  1
	if Heart.Hops > 0 {
		Heart.Addr = SELF_ADDR
		Heart.Id = Peers.GetSelfId()
		ForwardHeartBeat(Heart)
	}
}


/* AskForBlock
*
* Ask another server to return a block of certain height and hash
* http get to /localhost:port/block/{height}/{hash} (UploadBlock) to get the Block
*
*/

func AskForBlock(height int32, hash string) {
	PeerMap := Peers.GetPeerMap()
	for key, value := range PeerMap {
		fmt.Printf("key[%s] value[%d]\n", key, value)
		fmt.Println("height:", height)
		heightString := p2.ConvertIntToString(height)
		//http://localhost:8863/upload/1/xxxx
		prepareRequest := "http://" + key + ASK_PEERS + "/" + heightString + "/" + hash
		//http://localhost:8845:/block/5/hashvalue
		fmt.Println("PrepareRequest:", prepareRequest)
		response, err := http.Get(prepareRequest)
		fmt.Println("---> AskForBlock Sent  --->")
		if response.StatusCode == 204 {
			fmt.Println("There is no block available on Peer:", key)
		} else if response.StatusCode == 500 {
			fmt.Println("Internal Server Error on Peer:", key)
		}else{
			if err != nil {
				log.Fatal(err)
			}
			defer response.Body.Close()
			responseData, err := ioutil.ReadAll(response.Body)
			if err != nil {
				log.Fatal(err)
			}
			responseString := string(responseData)
			fmt.Println("Missing Block's JSON Response:",responseString)
			missingBlock := p4.Block{}
			missingBlock.DecodeFromJSON(responseString)
			//SBC.Insert(missingBlock)
			fmt.Println("Get Block after AskForBlock:", missingBlock)
			fmt.Println("From peer:", key)
			if !SBC.CheckParentHash(missingBlock) {
				fmt.Println("Recursive Call,missingBlock.Header.Height-1:" ,missingBlock.Header.Height-1,", missingBlock.Header.ParentHash",missingBlock.Header.ParentHash);
				AskForBlock(missingBlock.Header.Height-1,missingBlock.Header.ParentHash)
				fmt.Println("Get Block after recursively AskForBlock:", missingBlock)
				fmt.Println("From peer:", key)
			}
			SBC.Insert(missingBlock)
		}
	}
}

/* ForwardHeartBeat
*
* Send the HeartBeatData to all peers in local PeerMap after receiving
* Let other peers know about newly generated block
*
*/
func ForwardHeartBeat(heartBeatData data.HeartBeatData) {
	if heartBeatData.Hops != 0 {
		heartBeatData , _ := json.Marshal(heartBeatData)
		Peers.Rebalance()
		for addr,_ := range Peers.Copy() {
			resp, err := http.Post("http://"+ addr + "/heartbeat/receive", "application/json; charset=UTF-8", strings.NewReader(string(heartBeatData)))
			if err != nil || resp.StatusCode != 200 {
				fmt.Println("FATAL : ", err)
				Peers.Delete(addr)
			}
		}
	}
}

/* StartHeartBeat
*
* Start a while loop. Inside the loop, sleep for randomly 5~10 seconds,
* then use PrepareHeartBeatData() to create a
* HeartBeatData, and send it to all peers in the local PeerMap.
*
*/
func StartHeartBeat() {
	Peers.Rebalance()
	PeerMap := Peers.GetPeerMap()

	for key, value := range PeerMap {
		fmt.Printf("key[%s] value[%d]\n", key, value)
		uploadAddress := "http://" + key + "/heartbeat/receive"
		//destination := "http://localhost:6688" +/heartbeat/receive"
		peerMapToJson, err := Peers.PeerMapToJson()
		if err != nil {
			log.Fatal(err)
		}
		heartBearData:= data.PrepareHeartBeatData(&SBC, Peers.GetSelfId(), peerMapToJson, SELF_ADDR,false,"", p4.MerklePatriciaTrie{} ,&minerKey.PublicKey,false,"",0)
		jsonBytes, err := json.Marshal(heartBearData)
		req, err := http.NewRequest("POST", uploadAddress, bytes.NewBuffer(jsonBytes))
		req.Header.Set("X-Custom-Header", "myvalue")
		req.Header.Set("Content-Type", "application/json")
		client := &http.Client{}
		resp, err := client.Do(req)
		fmt.Println("---> HeartBeatSent --->")
		if err != nil {
			fmt.Println("FATAL: [",key,"] is deleted from Peer List")
			Peers.Delete(key)
			return
		}
		defer resp.Body.Close()
		body, _ := ioutil.ReadAll(resp.Body)
		fmt.Println("response Body:", string(body))
	}
}

/* StartTryingNonce()
*
* Generate block after solving hash puzzel
*
*/
func StartTryingNonce(){
	mpt:=p4.MerklePatriciaTrie{}
	mpt.Initial()
	//mpt.Insert("a","apple")
	//block:=p2.Block{}
	//block.Initial(1,"gensis",mpt,NONCE_ZERO)
	//block.Header.Nonce = NONCE_ZERO
	//SBC.Insert(block)
	isValidTransaction := false
	for {
	GetLatestBlock:
		blocks := SBC.GetLatestBlocks()
		STOP_GEN_BLOCK  = false
		var transactionJSON string
		var tempTransactionObject data.Transaction
		if len(TransactionMap) != 0 {
			for eventId, transactionObject := range TransactionMap {
				if transactionObject.Balance >= transactionObject.TransactionFee {
					//TODO: Add Signature
					isValidTransaction = true
					transactionObject.Balance = transactionObject.Balance - transactionObject.TransactionFee
					//TODO check how to add
					Heart.Balance = Heart.Balance + transactionObject.TransactionFee
					transactionJSON, _ = transactionObject.EncodeToJson()
					tempTransactionObject = transactionObject
					goto POW
				} else {
					delete(TransactionMap, eventId)
					fmt.Println("Transaction  Peer:", Peers.GetSelfId(),
						" is failed. Balance =", transactionObject.Balance)
				}
			}
		}
	POW:
		validateNonce := p4.StringRandom(16)
		hashPuzzle := string(blocks[0].Header.Hash) + string(validateNonce) + string(mpt.GetRoot())
		sum := sha3.Sum256([]byte(hashPuzzle))

		if strings.HasPrefix(hex.EncodeToString(sum[:]), NONCE_ZERO) {
			fmt.Println("HashPuzzle solved:",time.Now().Unix(), ", hashPuzzel:", hex.EncodeToString(sum[:]))
			peerMapJson,_ := Peers.PeerMapToJson()
			transactionJSON,_= tempTransactionObject.EncodeToJson()
			mpt.Insert(tempTransactionObject.EventId,transactionJSON)

			heartBeatData :=data.PrepareHeartBeatData(&SBC,Peers.GetSelfId(),peerMapJson,SELF_ADDR, true , validateNonce, mpt,&minerKey.PublicKey, isValidTransaction,transactionJSON, Heart.Balance)
			ForwardHeartBeat(heartBeatData)
			//isValidTransaction=false
			//mpt.Initial()
			//delete(TransactionMap, tempTransactionObject.EventId)
			if STOP_GEN_BLOCK  {
				fmt.Println("Stop generating node!")
				goto GetLatestBlock
			}
		}
	}
}

func Event(w http.ResponseWriter, r *http.Request) {

	log.Println("Event method is triggered")

	switch r.Method {
	case "GET":
		dir, err := os.Getwd()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("PWD:",dir)
		http.ServeFile(w, r, "Event.html")
	case "POST":
		if err := r.ParseForm(); err != nil {
			fmt.Fprintf(w, "ParseForm() err: %v", err)
			return
		}
		fmt.Fprintf(w, "HTTP Post = %v\n", r.PostForm)
		eventId := r.FormValue("eventId")
		eventName := r.FormValue("eventName")
		eventDate := r.FormValue("eventDate")
		eventDescription := r.FormValue("eventDescription")
		fmt.Fprintf(w, "Event ID: %s\n", eventId)
		fmt.Fprintf(w, "Event Name: %s\n", eventName)
		fmt.Fprintf(w, "Event Date: %s\n", eventDate)
		fmt.Fprintf(w, "Event Description: %s\n", eventDescription)

		newTimestamp := time.Now().Unix()

		//TODO calculate transaction fee
		//transactionFee:= data.TransactionFeeCalculation()
		newTransactionFee := 5
		newBalance := 100
		newTransactionObject := data.NewTransaction(eventId, eventName, newTimestamp, eventDescription, newTransactionFee, newBalance)
		fmt.Println("Transaction:", newTransactionObject)
		transactionJSON,_ := newTransactionObject.EncodeToJson()
		fmt.Println("Transaction JSON:",transactionJSON)
		TransactionMap[eventId] = newTransactionObject

		//Alper PeerMap or PublicKeyMap
		//publicKeyMap := Peers.GetPublicKeyMap()
		//for publicKey, port := range publicKeyMap {
		//	fmt.Printf("key[%s] value[%s]\n", publicKey, port)
		//
		//	cipherTextToMiner, hash, label, _:= data.Encrypt(transactionJSON,&minerKey.PublicKey)
		//
		//	fmt.Println("cipherTextToMiner is:", cipherTextToMiner )
		//	fmt.Println("hash is:", hash )
		//	fmt.Println("label is:", label )
		//
		//	signature, opts, hashed, newhash, _:= data.Sign(cipherTextToMiner, minerKey) //Private Key
		//	fmt.Println("User Signature is:", signature)
		//	fmt.Println("opts is:", opts)
		//	fmt.Println("hashed is:", hashed)
		//	fmt.Println("newhash is:", newhash)
		//}

		//plainTextfromRozita, _ := p5.Decrypt(cipherTextToMiner, hash , label ,minerKey.PrivateKey)
		//fmt.Println("plainTextfrom Rozita is:", plainTextfromRozita)

		//isVerified, _ := p5.Verification (RozitaKey.PublicKey, opts, hashed, newhash, signature)
		//fmt.Println("Is Verified is:", isVerified)

		fmt.Println("TransactionMap Size:",len(TransactionMap))

	default:
		fmt.Fprintf(w, "FATAL: Wrong HTTP Request!")
	}
}

