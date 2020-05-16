package http

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	ctypes "github.com/tendermint/tendermint/rpc/core/types"
)

type broadcastType int

const (
	bcastAsync  broadcastType = iota // sends blindly without waiting for whether the message is formed properly
	bcastSync                        // waits for CheckTx to ensure the message seems okay but does not wait for it to be made into a block
	bcastCommit                      // waits for the message to be made into a block (do not use in production code)
)

type transaction struct {
	pubKey    ed25519.PublicKey      // ed25519 public key, len=32
	signature []byte                 // ed25519 signature, len=64
	body      map[string]interface{} // encoded to JSON
}

func (serv *webService) broadcast(msg [][]interface{}, key ed25519.PrivateKey, bcastType broadcastType) error {
	if key == nil || msg != nil {
		return errors.New("nil message or key passed to broadcast")
	}
	if len(key) != ed25519.PrivateKeySize {
		return errors.New("Key with the wrong length passed to broadcast")
	}
	jsonResult, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	sign := ed25519.Sign(key, jsonResult)
	tx := append(append([]byte(key[ed25519.PublicKeySize:]), sign...), jsonResult...)

	var result *ctypes.ResultBroadcastTx

	switch bcastType {
	case bcastAsync:
		result, err = serv.RPC.BroadcastTxAsync(tx)
	case bcastSync:
		result, err = serv.RPC.BroadcastTxSync(tx)
	case bcastCommit:
		var resultCommit *ctypes.ResultBroadcastTxCommit
		resultCommit, err = serv.RPC.BroadcastTxCommit(tx)
		if err != nil {
			return err
		}
		if resultCommit.DeliverTx.Code != 0 {
			err = errors.New(resultCommit.DeliverTx.Info)
		} else if resultCommit.CheckTx.Code != 0 {
			err = errors.New(resultCommit.CheckTx.Info)
		}
	default:
		err = errors.New("bad bcastType provided")
	}
	if err != nil {
		return err
	}
	if result != nil && result.Code != 0 {
		return errors.New(result.Log)
	}

	return nil
}

func (serv *webService) stationID(w http.ResponseWriter, r *http.Request) {
	batch := serv.RPC.NewBatch()
	genesis, err := batch.Genesis()
	if err != nil {
		http.Error(w, "batch.Genesis: "+err.Error(), http.StatusInternalServerError)
		return
	}
	commit, err := batch.Commit(nil)
	if err != nil {
		http.Error(w, "batch.Commit: "+err.Error(), http.StatusInternalServerError)
		return
	}
	_, err = batch.Send()
	if err != nil {
		http.Error(w, "batch.Send: "+err.Error(), http.StatusInternalServerError)
		return
	}

	result := make(map[string]interface{})
	result["genesis"] = genesis.Genesis
	result["chain_id"] = commit.ChainID
	result["height"] = commit.Height
	result["hash"] = commit.LastCommitHash

	var jsonResult []byte
	jsonResult, err = json.Marshal(result)
	if err != nil {
		http.Error(w, "json.Marshal: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Add("Content-Type", "application/json")
	w.Write(jsonResult)
}

func (serv *webService) userLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "ParseForm: "+err.Error(), http.StatusInternalServerError)
		return
	}

	email := r.PostFormValue("username")
	if email == "" {
		http.Error(w, "Must specify a email", http.StatusBadRequest)
	}
	password := r.PostFormValue("password")
	if password == "" {
		http.Error(w, "Must specify a password", http.StatusBadRequest)
	}
	/*
		- POST:
			- grant_type: password
			- username:   Awesome.Avatarname
			- password:   supersecretpassword
			- scope:      owner
		- Reply:
			- `{ "access_token": "ca620f2725125348bef97e86695a7305dcd673e0d66105da043eede61d97db51", "created_at": 1577222914, "expires_in": 2629746, "refresh_token": "22170448f7fe2ab8122fbefadabb58fad05d665485628084895565286b5af96d", "scope": "owner", "token_type": "Bearer" }`
	*/
	http.Error(w, "Not Implemented (stub)", http.StatusNotImplemented)
}

func (serv *webService) userCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "ParseForm: "+err.Error(), http.StatusInternalServerError)
		return
	}

	username := r.PostFormValue("username")
	if username == "" {
		http.Error(w, "Must specify a username", http.StatusBadRequest)
	}
	email := r.PostFormValue("email")
	if email == "" {
		http.Error(w, "Must specify an email", http.StatusBadRequest)
	}
	password := r.PostFormValue("password")
	if password == "" {
		http.Error(w, "Must specify a password", http.StatusBadRequest)
	}
	salt, privKey, err := GenerateFromPassword(password)
	if err != nil {
		http.Error(w, "GenerateFromPassword: "+err.Error(), http.StatusInternalServerError)
		return
	}

	pubKey := base64.RawURLEncoding.EncodeToString(privKey[ed25519.PublicKeySize:])

	createUserKey := make(map[string]interface{})
	createUserKey["pubKey"] = pubKey
	createUserKey["salt"] = salt

	createEmailKey := make(map[string]interface{})
	createEmailKey["hash"] = sha256.Sum256([]byte(email))

	createUserTx := [][]interface{}{
		[]interface{}{fmt.Sprintf("user/%s/auth", username), createUserKey},
		[]interface{}{fmt.Sprintf("user/%s/email", username), createEmailKey},
	}

	err = serv.broadcast(createUserTx, privKey, bcastCommit)
	if err != nil {
		http.Error(w, "broadcast: "+err.Error(), http.StatusInternalServerError)
		return
	}

	http.Error(w, "User created successfully", http.StatusOK)
}