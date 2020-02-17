package main

import (
	"crypto/ed25519"
	"log"
)

func main() {
	//	priv := "e06d3183d14159228433ed599221b80bd0a5ce8352e4bdf0262f76786ef1c74db7e7a9fea2c0eb269d61e3b38e450a22e754941ac78479d6c54e1faf6037881d"
	//	pub := "b7e7a9fea2c0eb269d61e3b38e450a22e754941ac78479d6c54e1faf6037881d"
	//sig := "6834284b6b24c3204eb2fea824d82f88883a3d95e8b4a21b8c0ded553d17d17ddf9a8a7104b1258f30bed3787e6cb896fca78c58f8e03b5f18f14951a87d9a08"
	// d := hex.EncodeToString([]byte(priv))
	pubb, pvk, _ := ed25519.GenerateKey(nil)
	pvk2 := ed25519.NewKeyFromSeed(pvk[:32])
	//	privb, _ := hex.DecodeString(priv)
	//pvk := ed25519.PrivateKey(privb)
	buffer := []byte("4:salt6:foobar3:seqi1e1:v12:Hello World!")
	sigb := ed25519.Sign(pvk, buffer)
	//pubb, _ := hex.DecodeString(pub)
	//sigb2, _ := hex.DecodeString(sig)
	log.Println(ed25519.Verify(pubb, buffer, sigb))
	log.Printf("%x\n", pvk)
	log.Printf("%x\n", pvk.Public())
	log.Printf("%x\n", pubb)
	log.Printf("%x\n", sigb)
	log.Printf("%x\n", pvk2)
	//log.Printf("%x\n", sigb2)
}
