package data

import (
	"crypto/rsa"
)

/* TransactionJson Struct
*
* Data structure for transaction data
*
 */
type TransactionJson struct {
	publicKey   		string   `json:"publicKey"`
	eventId     		string   `json:"eventId"`
	eventName     		string   `json:"eventName"`
	timestamp     		string   `json:"eventDate"`
	eventDescription    string   `json:"eventDescription"`
	transactionFee    	string   `json:"transactionFee"`
}

/* Transaction Struct
*
* Data structure for transaction data
*
 */
type Transaction struct {
	publicKey   		*rsa.PublicKey
	eventId     		string
	eventName     		string
	timestamp  			int64
	eventDescription    string
	transactionFee    	int
}

/* NewTransactionJson()
*
* To return new transaction data in Json format
*
 */
func NewTransactionJson(publicKey string, eventId string, eventName string, timestamp string, eventDescription string, transactionFee string) TransactionJson {
	return TransactionJson{
		publicKey :  publicKey,
		eventId: eventId,
		eventName: eventName,
		timestamp: timestamp,
		eventDescription: eventDescription,
		transactionFee: transactionFee,
	}
}

/* NewTransaction()
*
* To return new transaction data
*
 */
func NewTransaction(publicKey *rsa.PublicKey, eventId string, eventName string, timestamp int64, eventDescription string, transactionFee int) Transaction {
	return Transaction{
		publicKey:  publicKey,
		eventId: eventId,
		eventName: eventName,
		timestamp: timestamp,
		eventDescription: eventDescription,
		transactionFee: transactionFee,
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
