//go:generate go run assets_generate.go
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/dgraph-io/badger"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	abci "github.com/tendermint/tendermint/abci/types"
	cfg "github.com/tendermint/tendermint/config"
	tmflags "github.com/tendermint/tendermint/libs/cli/flags"
	tmlog "github.com/tendermint/tendermint/libs/log"
	tmos "github.com/tendermint/tendermint/libs/os"
	tmrand "github.com/tendermint/tendermint/libs/rand"
	nm "github.com/tendermint/tendermint/node"
	"github.com/tendermint/tendermint/p2p"
	"github.com/tendermint/tendermint/privval"
	"github.com/tendermint/tendermint/proxy"
	"github.com/tendermint/tendermint/types"
	tmtime "github.com/tendermint/tendermint/types/time"
)

var firstCycleComplete chan struct{}

func doInit(config *cfg.Config, logger tmlog.Logger) error {
	// private validator
	privValKeyFile := config.PrivValidatorKeyFile()
	privValStateFile := config.PrivValidatorStateFile()

	if err := tmos.EnsureDir(filepath.Dir(privValKeyFile), 0700); err != nil {
		return errors.Wrap(err, "failed to create required folder")
	}
	if err := tmos.EnsureDir(filepath.Dir(privValStateFile), 0700); err != nil {
		return errors.Wrap(err, "failed to create required folder")
	}

	var pv *privval.FilePV
	if tmos.FileExists(privValKeyFile) {
		pv = privval.LoadFilePV(privValKeyFile, privValStateFile)
		logger.Info("Found private validator", "keyFile", privValKeyFile, "stateFile", privValStateFile)
	} else {
		pv = privval.GenFilePV(privValKeyFile, privValStateFile)
		pv.Save()
		logger.Info("Generated private validator", "keyFile", privValKeyFile, "stateFile", privValStateFile)
	}

	nodeKeyFile := config.NodeKeyFile()
	if err := tmos.EnsureDir(filepath.Dir(nodeKeyFile), 0700); err != nil {
		return errors.Wrap(err, "failed to create required folder")
	}
	if tmos.FileExists(nodeKeyFile) {
		logger.Info("Found node key", "path", nodeKeyFile)
	} else {
		if _, err := p2p.LoadOrGenNodeKey(nodeKeyFile); err != nil {
			return errors.Wrap(err, "failed to generate node key")
		}
		logger.Info("Generated node key", "path", nodeKeyFile)
	}

	// genesis file
	genFile := config.GenesisFile()
	if err := tmos.EnsureDir(filepath.Dir(genFile), 0700); err != nil {
		return errors.Wrap(err, "failed to create required folder")
	}
	if tmos.FileExists(genFile) {
		logger.Info("Found genesis file", "path", genFile)
	} else {
		genDoc := types.GenesisDoc{
			ChainID:         fmt.Sprintf("athenamesh-%v", tmrand.Str(6)),
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
			return errors.Wrap(err, "failed to create genesis file")
		}
		logger.Info("Generated genesis file", "path", genFile)
	}

	configFile := filepath.Join(filepath.Dir(nodeKeyFile), "config.toml")
	if !tmos.FileExists(configFile) {
		cfg.WriteConfigFile(configFile, config)
		logger.Info("Generated config file", "path", configFile)
	}

	logger.Info("")
	logger.Info("Initial configuration constructed.", "path", filepath.Dir(nodeKeyFile))
	logger.Info("Examine the configuration files to customize the behavior of the chain")
	logger.Info("Execute athenamesh in either \"once\" or \"node\" to initialize the new chain")
	return nil
}

func readAppConfig(config *cfg.Config, configFile string, logger tmlog.Logger) (tmlog.Logger, error) {
	// read config
	config.RootDir = filepath.Dir(filepath.Dir(configFile))
	viper.SetConfigFile(configFile)
	if err := viper.ReadInConfig(); err != nil {
		return nil, errors.Wrap(err, "viper failed to read config file")
	}
	if err := viper.Unmarshal(config); err != nil {
		return nil, errors.Wrap(err, "viper failed to unmarshal config")
	}
	if err := config.ValidateBasic(); err != nil {
		return nil, errors.Wrap(err, "config is invalid")
	}

	// create logger
	var err error
	logger, err = tmflags.ParseLogLevel(config.LogLevel, logger, cfg.DefaultLogLevel())
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse log level")
	}

	return logger, nil
}

func instantiateApp(app abci.Application, config *cfg.Config, logger tmlog.Logger) (*nm.Node, error) {

	// read private validator
	pv := privval.LoadFilePV(
		config.PrivValidatorKeyFile(),
		config.PrivValidatorStateFile(),
	)

	// read node key
	nodeKey, err := p2p.LoadNodeKey(config.NodeKeyFile())
	if err != nil {
		return nil, errors.Wrap(err, "failed to load node's key")
	}

	// create node
	node, err := nm.NewNode(
		config,
		pv,
		nodeKey,
		proxy.NewLocalClientCreator(app),
		nm.DefaultGenesisDocProviderFunc(config),
		nm.DefaultDBProvider,
		nm.DefaultMetricsProvider(config.Instrumentation),
		logger)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create new Tendermint node")
	}

	return node, nil
}

func prepareNode(config *cfg.Config, logger tmlog.Logger) (*nm.Node, *badger.DB, error) {
	configFile := filepath.Join(filepath.Dir(config.NodeKeyFile()), "config.toml")

	var err error
	flag.Parse()
	logger, err = readAppConfig(config, configFile, logger)
	if err != nil {
		return nil, nil, err
	}

	dbPath := filepath.Join(filepath.Dir(config.PrivValidatorStateFile()), "store.db")
	dbopt := badger.DefaultOptions(dbPath)
	badgerLogger := newBadgerLogger(logger)
	dbopt.Logger = badgerLogger
	if strings.HasPrefix(runtime.GOOS, "windows") {
		dbopt = dbopt.WithTruncate(true)
	}
	db, err := badger.Open(dbopt)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to open badger db")
	}
	app := NewAthenaStoreApplication(db, logger)

	node, err := instantiateApp(app, config, logger)

	return node, db, err
}

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
	args := os.Args[1:]
	if len(args) > 0 {
		switch args[0] {
		case "init":
			err := doInit(config, logger)
			if err != nil {
				logger.Error(err.Error())
				os.Exit(1)
			}
			return
		case "node":
			mainAction = actionNode
		case "once":
			mainAction = actionOnce
		default:
			logger.Error(fmt.Sprintf("action \"%s\" is unrecognized", args[0]))
		}
	}
	if mainAction == actionNone {
		logger.Error("athenamesh.exe <command>")
		logger.Error("  init - create a new (empty) database.  This will create a new \"universe\"")
		logger.Error("  once - operate a node for one cycle only (useful when creating a new \"universe\")")
		logger.Error("  node - operate a node")
		return
	}

	node, db, err := prepareNode(config, logger)
	if err != nil {
		logger.Error(err.Error())
		if db != nil {
			db.Close()
		}
		os.Exit(1)
	}

	if mainAction == actionOnce {
		firstCycleComplete = make(chan struct{}, 1)
	}

	// start the tendermint node here, while prepping to shutdown properly
	node.Start()
	defer func() {
		node.Stop()
		node.Wait()
		db.Close()
	}()

	switch mainAction {
	case actionOnce:
		<-firstCycleComplete
	case actionNode:
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		<-c
	}
}
