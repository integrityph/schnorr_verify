package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"slices"

	ecies1 "github.com/ecies/go/v2"
	"github.com/integrityph/schnorr_verify/ecies"
)

var EC_PRIVATE_KEY = "7efc46b059d4d6bfc6eb05ad92ec5c862f4c853f00fcb166e1602bfab5e0f0e0"
var EC_PUBLIC_KEY = "04d5529d1c8b4b370bd724315bb4844f7c3bccbb4068bc6e97b97d7b02ba382597659465229a78839862e1d71e746241b652b762c0116c4c1cf2a258578f627a00"

func standard() {
	msg := []byte("Helloooo")

	pubKey, _ := ecies1.NewPublicKeyFromHex(EC_PUBLIC_KEY)
	ct, _ := ecies1.Encrypt(pubKey, msg)

	privateKey, _ := ecies1.NewPrivateKeyFromHex(EC_PRIVATE_KEY)
	msgProduced, _ := ecies1.Decrypt(privateKey, ct)

	fmt.Println("Roundtrip worked on Standard", slices.Equal(msg, msgProduced))
}

func mine() {
	msg := []byte("Helloooo")

	pubKey, err := ecies.NewPublicKeyFromHex(EC_PUBLIC_KEY)
	if err != nil {
		log.Fatalln("err1", err)
	}

	ct, err := ecies.Encrypt(pubKey, msg)
	if err != nil {
		log.Fatalln("err2", err)
	}

	privateKey, err := ecies.NewPrivateKeyFromHex(EC_PRIVATE_KEY)
	if err != nil {
		log.Fatalln("err3", err)
	}
	msgProduced, err := ecies.Decrypt(privateKey, ct)
	if err != nil {
		log.Fatalln("err4", err)
	}

	fmt.Println("Roundtrip worked on Mine", slices.Equal(msg, msgProduced))
	fmt.Println(hex.EncodeToString(msg), hex.EncodeToString(msgProduced))
	fmt.Println(hex.EncodeToString(msg))
}

func main() {
	standard()
	mine()
}
