package data

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"hash"
	"os"
)

/* VerificationKey Struct
*
* Verification Key data structure
*
 */
type VerificationKeyJson struct {
	PublicKey   string   `json:"publickey"` //DataStructure
	PrivateKey  string  `json:"privatekey"`
}

type VerificationKey struct {
	PublicKey   *rsa.PublicKey
	PrivateKey  *rsa.PrivateKey
}


/* NewVerificationKey()
*
* NewHeartBeatData() is a normal initial function which creates an instance
*
 */
func NewVerificationKeyJson(PublicKey string, PrivateKey string) VerificationKeyJson {
	return VerificationKeyJson{
		PublicKey:  PublicKey,
		PrivateKey: PrivateKey,
	}
}

func NewVerificationKey(privateKey *rsa.PrivateKey,publicKey *rsa.PublicKey) VerificationKey {
	return VerificationKey{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}
}

/* PrepareHeartBeatData()
*
* PrepareHeartBeatData() is used when you want to send a HeartBeat to other peers.
* PrepareHeartBeatData would first create a new instance of HeartBeatData, then decide
* whether or not you will create a new block and send the new block to other peers.
*
 */
func RegisterVerificationKey() VerificationKeyJson{

	privateKey, err := rsa.GenerateKey(rand.Reader, 2014)
	if err != nil {
		return NewVerificationKeyJson("", "")
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
		return NewVerificationKeyJson("", "")
	}

	publicKeyBlock := pem.Block{
		Type:    "PUBLIC KEY",
		Headers: nil,
		Bytes:   publicKeyDer,
	}
	publicKeyPem := string(pem.EncodeToMemory(&publicKeyBlock))

	//fmt.Println(privateKeyPem)
	//fmt.Println(publicKeyPem)

	return NewVerificationKeyJson(publicKeyPem, privateKeyPem)
}

func GenerateKey() VerificationKey{
	//publicKey := new(rsa.PublicKey)
	//privateKey := new(rsa.PrivateKey)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println(err.Error)
		os.Exit(1)
	}
	publicKey := &privateKey.PublicKey
	return NewVerificationKey(privateKey, publicKey)
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


func Encrypt(messageJson string, pubLicKey *rsa.PublicKey) ([]byte, hash.Hash, []byte, error){
	message := []byte(messageJson)
	label := []byte("")
	hash := sha256.New()
	ciphertext, err := rsa.EncryptOAEP(
		hash,
		rand.Reader,
		pubLicKey,
		message,
		label,
	)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	//fmt.Printf("OAEP encrypted [%s] to \n[%x]\n", string(message), ciphertext)
	return ciphertext, hash, label, err
}


func Sign(message []byte, privateKey *rsa.PrivateKey) ([]byte, rsa.PSSOptions, []byte, crypto.Hash, error){
	//messageByte := []byte(message)
	var opts rsa.PSSOptions
	opts.SaltLength = rsa.PSSSaltLengthAuto // for simple example
	PSSmessage := message
	newhash := crypto.SHA256
	pssh := newhash.New()
	pssh.Write(PSSmessage)
	hashed := pssh.Sum(nil)
	signature, err := rsa.SignPSS(
		rand.Reader,
		privateKey,
		newhash,
		hashed,
		&opts,
	)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	//fmt.Printf("PSS Signature : %x\n", signature)
	return signature, opts, hashed, newhash, err
}

func Decrypt (ciphertext []byte, hash hash.Hash, label []byte,privateKey *rsa.PrivateKey) (string, error){

	plainText, err := rsa.DecryptOAEP(
		hash,
		rand.Reader,
		privateKey,
		ciphertext,
		label,
	)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	//fmt.Printf("OAEP decrypted [%x] to \n[%s]\n", ciphertext, plainText)
	plainTextJson := string(plainText) //TODO Check if it is in byte or string
	return plainTextJson, err
}

func Verification (publicKey *rsa.PublicKey, opts rsa.PSSOptions, hashed []byte, newhash crypto.Hash, signature []byte) (bool,error){
	isVerify := false
	err := rsa.VerifyPSS(
		publicKey,
		newhash,
		hashed,
		signature,
		&opts,
	)
	if err != nil {
		fmt.Println("Verify Signature failed!!!")
		isVerify = false
		os.Exit(1)
	} else {
		fmt.Println("Verify Signature successful...")
		isVerify = true
	}

	return isVerify, err
}
