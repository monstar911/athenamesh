package http

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/odysseus654/athenamesh/common"

	rpchttp "github.com/tendermint/tendermint/rpc/client/http"
)

type webService struct {
	RPCPort int
	Prefix  string
	RPC     *rpchttp.HTTP
	Server  *http.Server
	Mux     *http.ServeMux
}

func webStub(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Not Implemented (stub)", http.StatusNotImplemented)
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
	password := r.PostFormValue("password")
	if password == "" {
		http.Error(w, "Must specify a password", http.StatusBadRequest)
	}
	salt, privKey, err := GenerateFromPassword(password)
	if err != nil {
		http.Error(w, "GenerateFromPassword: "+err.Error(), http.StatusInternalServerError)
		return
	}

	_ = username
	_ = salt
	_ = privKey

	http.Error(w, "Not Implemented (stub)", http.StatusNotImplemented)
}

func (serv *webService) prepareServer() error {
	mux := http.NewServeMux()
	serv.Mux = mux

	mux.HandleFunc(serv.Prefix+"/domains/", webStub)
	mux.HandleFunc(serv.Prefix+"/domains/temporary", webStub)
	mux.HandleFunc(serv.Prefix+"/oauth/token", serv.userLogin)
	mux.HandleFunc(serv.Prefix+"/places", webStub)
	mux.HandleFunc(serv.Prefix+"/snapshots", webStub)
	mux.HandleFunc(serv.Prefix+"/station", serv.stationID)
	mux.HandleFunc(serv.Prefix+"/user/channel_user", webStub)
	mux.HandleFunc(serv.Prefix+"/user/connection_request", webStub)
	mux.HandleFunc(serv.Prefix+"/user/connections/", webStub)
	mux.HandleFunc(serv.Prefix+"/user/create", serv.userCreate)
	mux.HandleFunc(serv.Prefix+"/user/domains/", webStub)
	mux.HandleFunc(serv.Prefix+"/user/friends/", webStub)
	mux.HandleFunc(serv.Prefix+"/user/heartbeat", webStub)
	mux.HandleFunc(serv.Prefix+"/user/location", webStub)
	mux.HandleFunc(serv.Prefix+"/user/locker", webStub)
	mux.HandleFunc(serv.Prefix+"/user/places", webStub)
	mux.HandleFunc(serv.Prefix+"/user/profile", webStub)
	mux.HandleFunc(serv.Prefix+"/user/security", webStub)
	mux.HandleFunc(serv.Prefix+"/user_activities", webStub)
	mux.HandleFunc(serv.Prefix+"/user_stories", webStub)
	mux.HandleFunc(serv.Prefix+"/users", webStub)

	return nil
}

// Start launching the web service
func (serv *webService) Start(ctx context.Context) error {
	var err error
	serv.RPC, err = rpchttp.New(fmt.Sprintf("http://127.0.0.1:%d", serv.RPCPort), "/websocket")
	if err != nil {
		return err
	}

	serv.Server = &http.Server{Addr: ":21478", Handler: serv.Mux}
	return serv.Server.ListenAndServe()
}

// Stop shuts down the web service
func (serv *webService) Stop(ctx context.Context) error {
	var err error
	if serv.Server != nil {
		err = serv.Server.Shutdown(ctx)
		serv.Server = nil
	}
	if serv.RPC != nil {
		err2 := serv.RPC.Stop()
		if err2 != nil {
			err = err2
		}
	}
	return err
}

// NewWebService creates and returns a new webservice
func NewWebService(rpcPort int, prefix string) (common.Service, error) {
	serv := &webService{
		RPCPort: rpcPort,
		Prefix:  prefix,
	}
	err := serv.prepareServer()
	return serv, err
}
