package http

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	rpchttp "github.com/tendermint/tendermint/rpc/client/http"
)

type WebService struct {
	RPCPort int
	Prefix  string
	RPC     *rpchttp.HTTP
	Server  *http.Server
	Mux     *http.ServeMux
}

func webStub(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
	w.Write([]byte("Not Implemented (stub)"))
}

func webError(w http.ResponseWriter, err error) {
	w.WriteHeader(http.StatusInternalServerError)
	w.Write([]byte(err.Error()))
}

func (serv *WebService) stationID(w http.ResponseWriter, r *http.Request) {
	batch := serv.RPC.NewBatch()
	genesis, err := batch.Genesis()
	if err != nil {
		webError(w, err)
		return
	}
	commit, err := batch.Commit(nil)
	if err != nil {
		webError(w, err)
		return
	}
	_, err = batch.Send()
	if err != nil {
		webError(w, err)
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
		webError(w, err)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Add("Content-Type", "application/json")
	w.Write(jsonResult)
}

func (serv *WebService) userLogin(w http.ResponseWriter, r *http.Request) {
	/*
		- POST:
			- grant_type: password
			- username:   Awesome.Avatarname
			- password:   supersecretpassword
			- scope:      owner
		- Reply:
			- `{ "access_token": "ca620f2725125348bef97e86695a7305dcd673e0d66105da043eede61d97db51", "created_at": 1577222914, "expires_in": 2629746, "refresh_token": "22170448f7fe2ab8122fbefadabb58fad05d665485628084895565286b5af96d", "scope": "owner", "token_type": "Bearer" }`
	*/
	w.WriteHeader(http.StatusNotImplemented)
	w.Write([]byte("Not Implemented (stub)"))
}

func (serv *WebService) userCreate(w http.ResponseWriter, r *http.Request) {
	/*
		- POST:
			- grant_type: password
			- username:   Awesome.Avatarname
			- password:   supersecretpassword
			- scope:      owner
		- Reply:
			- `{ "access_token": "ca620f2725125348bef97e86695a7305dcd673e0d66105da043eede61d97db51", "created_at": 1577222914, "expires_in": 2629746, "refresh_token": "22170448f7fe2ab8122fbefadabb58fad05d665485628084895565286b5af96d", "scope": "owner", "token_type": "Bearer" }`
	*/
	w.WriteHeader(http.StatusNotImplemented)
	w.Write([]byte("Not Implemented (stub)"))
}

func (serv *WebService) prepareServer() error {
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

func (serv *WebService) Start(ctx context.Context) error {
	var err error
	serv.RPC, err = rpchttp.New(fmt.Sprintf("http://127.0.0.1:%d", serv.RPCPort), "/websocket")
	if err != nil {
		return err
	}

	serv.Server = &http.Server{Addr: ":21478", Handler: serv.Mux}
	return serv.Server.ListenAndServe()
}

func (serv *WebService) Stop(ctx context.Context) error {
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

func NewWebService(rpcPort int, prefix string) (serv *WebService, err error) {
	serv = &WebService{
		RPCPort: rpcPort,
		Prefix:  prefix,
	}
	err = serv.prepareServer()
	return
}
