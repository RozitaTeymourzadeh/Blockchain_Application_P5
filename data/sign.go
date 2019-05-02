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

/* VerificationKeyJson Struct
*
* Verification Key data structure in Json format
*
 */
type VerificationKeyJson struct {
	PublicKey   string   `json:"publickey"` //DataStructure
	PrivateKey  string  `json:"privatekey"`
}

/* VerificationKey Struct
*
* Verification Key data structure
*
 */
type VerificationKey struct {
	PublicKey   *rsa.PublicKey
	PrivateKey  *rsa.PrivateKey
}


/* NewVerificationKeyJson()
*
* Return Verification data in Json format
*
 */
func NewVerificationKeyJson(publicKey string, privateKey string) VerificationKeyJson {
	return VerificationKeyJson{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}
}


/* NewVerificationKey()
*
* Return Verification data
*
 */
func NewVerificationKey(privateKey *rsa.PrivateKey,publicKey *rsa.PublicKey) VerificationKey {
	return VerificationKey{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}
}

/* GenerateKeyString()
*
* To generate key in string format
*
 */
func GenerateKeyString() VerificationKeyJson{

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

/* GenerateKey()
*
* To generate key
*
 */
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

/* Encrypt()
*
* To Encrypt message
*
 */
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

/* Decrypt()
*
* To Decrypt message
*
 */
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


/* Sign()
*
* To sign message
*
 */
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

/* Verify()
*
* To verify message
*
 */
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
