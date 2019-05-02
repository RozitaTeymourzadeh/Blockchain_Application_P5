	package main

	import (
		"MerklePatriciaTree/p5/Blockchain_Application_P5/data"
		"MerklePatriciaTree/p5/Blockchain_Application_P5/p5"
		"fmt"
		"log"
		"net/http"
		"os"
	)

	func main() {

		NimaKey := data.GenerateKey()
		RozitaKey := data.GenerateKey()

		fmt.Println("Private Key : ", RozitaKey.PrivateKey)
		fmt.Println("Public key ", RozitaKey.PublicKey)
		fmt.Println("Private Key : ", NimaKey.PrivateKey)
		fmt.Println("Public key ", NimaKey.PublicKey)


		message := "Hi I am Rozita !!!!!"
		cipherTexttoNima, hash, label, _:= data.Encrypt(message, NimaKey.PublicKey)
		fmt.Println("cipherTexttoNima is:", cipherTexttoNima )

		signature, opts, hashed, newhash, _:= data.Sign(cipherTexttoNima, RozitaKey.PrivateKey)
		fmt.Println("Rozita Signature is:", signature)

		plainTextfromRozita, _ := data.Decrypt(cipherTexttoNima, hash , label ,NimaKey.PrivateKey)
		fmt.Println("plainTextfrom Rozita is:", plainTextfromRozita)

		isVerified, _ := data.Verification (RozitaKey.PublicKey, opts, hashed, newhash, signature)
		fmt.Println("Is Verified is:", isVerified)


		router := p5.NewRouter()
		if len(os.Args) > 1 {
			log.Fatal(http.ListenAndServe(":" + os.Args[1], router))
		} else {
			log.Fatal(http.ListenAndServe(":6686", router))
		}


	}
