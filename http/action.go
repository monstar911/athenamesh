package http

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

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

func (serv *webService) query(path string, key ed25519.PrivateKey) (interface{}, error) {
	if path == "" {
		return nil, errors.New("empty path passed to query")
	}

	var sign []byte
	if key != nil {
		if len(key) != ed25519.PrivateKeySize {
			return nil, errors.New("Key with the wrong length passed to query")
		}
		sign = ed25519.Sign(key, []byte(path))
	}

	result, err := serv.RPC.ABCIQuery(path, sign)
	if err != nil {
		return nil, err
	}
	if result.Response.Code != 0 {
		return nil, errors.New(result.Response.Info)
	}
	if result.Response.Value == nil {
		return nil, nil
	}

	var value interface{}
	decoder := json.NewDecoder(strings.NewReader(string(result.Response.Value)))
	decoder.UseNumber()
	if err = decoder.Decode(&value); err != nil {
		return nil, err
	}
	return value, nil
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

	// retrieve the values from the user
	email := r.PostFormValue("username")
	if email == "" {
		http.Error(w, "Must specify an email", http.StatusBadRequest)
	}
	password := r.PostFormValue("password")
	if password == "" {
		http.Error(w, "Must specify a password", http.StatusBadRequest)
	}

	// try to query for the pubKey and salt from the mesh
	emailHash := sha256.Sum256([]byte(email))
	queryKey := fmt.Sprintf("users/email/%s:auth", base64.RawURLEncoding.EncodeToString(emailHash[:]))
	genResult, err := serv.query(queryKey, nil)
	if err != nil {
		http.Error(w, "user query: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if genResult == nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	result, ok := genResult.(map[string]interface{})
	if !ok {
		http.Error(w, "user query returned non-map result", http.StatusInternalServerError)
		return
	}
	genUserPubKey, ok := result["pubKey"]
	if !ok {
		http.Error(w, "user query missing pubKey attribute", http.StatusInternalServerError)
		return
	}
	strUserPubKey, ok := genUserPubKey.(string)
	if !ok {
		http.Error(w, "user query has non-string pubKey attribute", http.StatusInternalServerError)
		return
	}
	userPubKey, err := base64.RawURLEncoding.DecodeString(strUserPubKey)
	if err != nil {
		http.Error(w, "decoding user query pubKey attribute: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if len(userPubKey) != ed25519.PublicKeySize {
		http.Error(w, "user query has pubkey with unexpected length", http.StatusInternalServerError)
		return
	}
	genSalt, ok := result["salt"]
	if !ok {
		http.Error(w, "user query missing salt attribute", http.StatusInternalServerError)
		return
	}
	strSalt, ok := genSalt.(string)
	if !ok {
		http.Error(w, "user query has non-string salt attribute", http.StatusInternalServerError)
		return
	}

	// generate our public + private key
	privKey, err := KeyFromPassword(strSalt, password)
	if err != nil {
		http.Error(w, "KeyFromPassword: "+err.Error(), http.StatusInternalServerError)
		return
	}
	pubKey := privKey[ed25519.PublicKeySize:]

	if bytes.Compare(pubKey, userPubKey) != 0 {
		http.Error(w, "Login failed", http.StatusUnauthorized)
		return
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

	// retrieve the values from the user
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

	// generate our public + private key
	salt, privKey, err := GenerateFromPassword(password)
	if err != nil {
		http.Error(w, "GenerateFromPassword: "+err.Error(), http.StatusInternalServerError)
		return
	}
	pubKey := base64.RawURLEncoding.EncodeToString(privKey[ed25519.PublicKeySize:])

	// submit the createUser request to the mesh
	createUserKey := map[string]interface{}{
		"pubKey": pubKey,
		"salt":   salt,
	}
	emailHash := sha256.Sum256([]byte(email))
	createEmailKey := map[string]interface{}{
		"hash": base64.RawURLEncoding.EncodeToString(emailHash[:]),
	}

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
