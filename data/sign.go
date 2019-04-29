package data

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
)

/* VerificationKey Struct
*
* Verification Key data structure
*
 */
type VerificationKey struct {
	PublicKey   string   `json:"publickey"` //DataStructure
	PrivateKey  string  `json:"privatekey"`
}


/* NewVerificationKey()
*
* NewHeartBeatData() is a normal initial function which creates an instance
*
 */
func NewVerificationKey(PublicKey string, PrivateKey string) VerificationKey {
	return VerificationKey{
		PublicKey:  PublicKey,
		PrivateKey: PrivateKey,
	}
}

/* PrepareHeartBeatData()
*
* PrepareHeartBeatData() is used when you want to send a HeartBeat to other peers.
* PrepareHeartBeatData would first create a new instance of HeartBeatData, then decide
* whether or not you will create a new block and send the new block to other peers.
*
 */
func RegisterVerificationKey() VerificationKey{

	privateKey, err := rsa.GenerateKey(rand.Reader, 2014)
	if err != nil {
		return NewVerificationKey("", "")
	}

	privateKeyDer := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privateKeyDer,
	}
	privateKeyPem := string(pem.EncodeToMemory(&privateKeyBlock))

	publicKey := privateKey.PublicKey
	publicKeyDer, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		return NewVerificationKey("", "")
	}

	publicKeyBlock := pem.Block{
		Type:    "PUBLIC KEY",
		Headers: nil,
		Bytes:   publicKeyDer,
	}
	publicKeyPem := string(pem.EncodeToMemory(&publicKeyBlock))

	//fmt.Println(privateKeyPem)
	//fmt.Println(publicKeyPem)

	return NewVerificationKey(publicKeyPem, privateKeyPem)
}

/* EncodeToJson()
*
* To Encode HeartBeatData from json format
*
 */
func (key *VerificationKey) EncodeToJson() (string, error) {
	jsonBytes, error := json.Marshal(key)
	return string(jsonBytes), error
}

/* DecodeFromJson()
*
* To Decode HeartBeatData from json format
*
 */
func (key *VerificationKey) DecodeFromJson(jsonString string) error {
	return json.Unmarshal([]byte(jsonString), key)
}


