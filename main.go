//go:generate go run assets_generate.go
package main

import (
	"bufio"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"log"
	"os"

	cfg "github.com/tendermint/tendermint/config"
	tmlog "github.com/tendermint/tendermint/libs/log"
	tmrand "github.com/tendermint/tendermint/libs/rand"
	"github.com/tendermint/tendermint/p2p"
	"github.com/tendermint/tendermint/privval"
	"github.com/tendermint/tendermint/types"
	tmtime "github.com/tendermint/tendermint/types/time"
)

var logger = tmlog.NewTMLogger(tmlog.NewSyncWriter(os.Stdout))

func retrieveDefaultConfig() (interface{}, error) {
	file, err := Resources.Open("default_config.json")
	if err != nil {
		return nil, err
	}
	defer file.Close()
	decoder := json.NewDecoder(bufio.NewReader(file))
	var result interface{}
	err = decoder.Decode(&result)
	return result, err
}

// DefaultConfig represents the default configuration when none is available
var DefaultConfig interface{}

func doInit() error {
	// private validator
	config := cfg.DefaultConfig()
	privValKeyFile := config.PrivValidatorKeyFile()
	privValStateFile := config.PrivValidatorStateFile()
	pv := privval.GenFilePV(privValKeyFile, privValStateFile)
	pv.Save()
	logger.Info("Generated private validator", "keyFile", privValKeyFile, "stateFile", privValStateFile)

	nodeKeyFile := config.NodeKeyFile()
	if _, err := p2p.LoadOrGenNodeKey(nodeKeyFile); err != nil {
		return err
	}
	logger.Info("Generated node key", "path", nodeKeyFile)

	// genesis file
	genFile := config.GenesisFile()
	genDoc := types.GenesisDoc{
		ChainID:         fmt.Sprintf("test-chain-%v", tmrand.Str(6)),
		GenesisTime:     tmtime.Now(),
		ConsensusParams: types.DefaultConsensusParams(),
	}
	key := pv.GetPubKey()
	genDoc.Validators = []types.GenesisValidator{{
		Address: key.Address(),
		PubKey:  key,
		Power:   10,
	}}

	if err := genDoc.SaveAs(genFile); err != nil {
		return err
	}
	logger.Info("Generated genesis file", "path", genFile)
	return nil
}

func doNode() {

}

func main() {
	doInit()
	return

	args := os.Args[1:]
	if len(args) > 0 {
		switch args[0] {
		case "init":
			doInit()
			return
		case "node":
			doNode()
			return
		}
	}
	var err error
	DefaultConfig, err = retrieveDefaultConfig()
	if err != nil {
		panic(err.Error())
	}

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
