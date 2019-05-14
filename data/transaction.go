package data

import (
	//"crypto/rsa"
	"crypto/rsa"
	"encoding/json"
)

/* TransactionJson Struct
*
* Data structure for transaction data
*
 */
type TransactionJson struct {
	PublicKey   		string   `json:"publicKey"`
	EventId     		string   `json:"eventId"`
	EventName     		string   `json:"eventName"`
	Timestamp     		string   `json:"eventDate"`
	EventDescription    string   `json:"eventDescription"`
	TransactionFee    	string   `json:"transactionFee"`
	Balance				string	 `json:"balance"`
}

/* Transaction Struct
*
* Data structure for transaction data
*
 */
type Transaction struct {
	//*rsa.PublicKey
	PublicKey   		*rsa.PublicKey
	EventId     		string
	EventName     		string
	Timestamp  			int64
	EventDescription    string
	TransactionFee    	int
	Balance				int
}

/* NewTransactionJson()
*
* To return new transaction data in Json format
*
 */
//publicKey string
func NewTransactionJson(eventId string, eventName string, timestamp string, eventDescription string, transactionFee string, balance string) TransactionJson {
	return TransactionJson{
		//PublicKey :  publicKey,
		EventId: eventId,
		EventName: eventName,
		Timestamp: timestamp,
		EventDescription: eventDescription,
		TransactionFee: transactionFee,
		Balance: balance,
	}
}

/* NewTransaction()
*
* To return new transaction data
*
 */
//publicKey *rsa.PublicKey
func NewTransaction( eventId string, eventName string, timestamp int64, eventDescription string, transactionFee int, balance int) Transaction {
	return Transaction{

		//PublicKey:  publicKey,
		EventId: eventId,
		EventName: eventName,
		Timestamp: timestamp,
		EventDescription: eventDescription,
		TransactionFee: transactionFee,
		Balance: balance,
	}
}

/* TransactionFeeCalculation()
*
* To calculate transaction fee for generating block
*
 */
func TransactionFeeCalculation(blockJson string) int{
	transactionFee := (len(blockJson)* 2)/10
	return transactionFee
}

/* EncodeToJson()
*
* To Encode Transaction from json format
*
 */
func (transaction *Transaction) EncodeToJson() (string, error) {
	jsonBytes, error := json.Marshal(transaction)
	return string(jsonBytes), error
}

/* DecodeFromJson()
*
* To Decode HeartBeatData from json format
*
 */
func (transaction *Transaction) DecodeFromJson(jsonString string) error {
	return json.Unmarshal([]byte(jsonString), transaction)
}