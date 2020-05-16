//go:generate go run http/assets_generate.go
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/odysseus654/athenamesh/app"

	cfg "github.com/tendermint/tendermint/config"
	tmlog "github.com/tendermint/tendermint/libs/log"
)

type mainAction int

const (
	actionNone mainAction = iota
	actionNode
	actionOnce
)

func main() {
	config := cfg.DefaultConfig()
	logger := tmlog.NewTMLogger(tmlog.NewSyncWriter(os.Stdout))

	mainAction := actionNone
	var service app.Service
	var err error
	args := os.Args[1:]
	if len(args) > 0 {
		switch args[0] {
		case "init":
			err := app.DoInit(config, logger)
			if err != nil {
				logger.Error(err.Error())
				os.Exit(1)
			}
			return
		case "node":
			mainAction = actionNode
			service, err = app.NewFullNode(config, logger)
		case "once":
			mainAction = actionOnce
			service, err = app.NewFullNode(config, logger)
		default:
			logger.Error(fmt.Sprintf("action \"%s\" is unrecognized", args[0]))
		}
	}
	if mainAction == actionNone {
		logger.Error("athenamesh.exe <command>")
		logger.Error("  node - operate a full node")
		logger.Error("  once - operate a full node for one cycle only (useful when creating a new chain)")
		logger.Error("  init - create a new (empty) database.  This will create a new chain")
		return
	}
	if err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}

	if mainAction == actionOnce {
		app.FirstCycleComplete = make(chan struct{}, 1)
	}

	// start the tendermint node here, while prepping to shutdown properly
	err = service.Start(context.Background())
	if err != nil {
		logger.Error(err.Error())
		service.Stop(context.Background())
		os.Exit(1)
	}
	defer service.Stop(context.Background())

	switch mainAction {
	case actionOnce:
		<-app.FirstCycleComplete
	case actionNode:
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		<-c
	}
}
