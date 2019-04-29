	package main

	import (
		//"MerklePatriciaTree/p3/cs686-blockchain-p3-RozitaTeymourzadeh/p3"
		"MerklePatriciaTree/p4/Blockchain_Application_P5/data"
		"fmt"

		//"crypto/rand"
		//"crypto/rsa"
		//"crypto/x509"
		//"encoding/pem"
		//"fmt"
		//"log"
		//"net/http"
		//"os"
	)

	func main() {
		//router := p3.NewRouter()
		//if len(os.Args) > 1 {
		//	log.Fatal(http.ListenAndServe(":" + os.Args[1], router))
		//} else {
		//	log.Fatal(http.ListenAndServe(":6686", router))
		//}

			//privateKey, err := rsa.GenerateKey(rand.Reader, 2014)
			//if err != nil {
			//	return
			//}
			//
			//privateKeyDer := x509.MarshalPKCS1PrivateKey(privateKey)
			//privateKeyBlock := pem.Block{
			//	Type:    "RSA PRIVATE KEY",
			//	Headers: nil,
			//	Bytes:   privateKeyDer,
			//}
			//privateKeyPem := string(pem.EncodeToMemory(&privateKeyBlock))
			//
			//publicKey := privateKey.PublicKey
			//publicKeyDer, err := x509.MarshalPKIXPublicKey(&publicKey)
			//if err != nil {
			//	return
			//}
			//
			//publicKeyBlock := pem.Block{
			//	Type:    "PUBLIC KEY",
			//	Headers: nil,
			//	Bytes:   publicKeyDer,
			//}
			//publicKeyPem := string(pem.EncodeToMemory(&publicKeyBlock))
			//
			//fmt.Println(privateKeyPem)
			//fmt.Println(publicKeyPem)

			verificationKey := data.RegisterVerificationKey()
			fmt.Println(verificationKey.PrivateKey)
			fmt.Println(verificationKey.PublicKey)
	}
