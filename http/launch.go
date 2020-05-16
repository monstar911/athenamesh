package http

import (
	"context"
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
