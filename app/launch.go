package app

// Manages a tendermint instance built around our ABCI application

import (
	"context"
	"flag"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/odysseus654/athenamesh/common"

	"github.com/dgraph-io/badger"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	abcitypes "github.com/tendermint/tendermint/abci/types"
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

// FirstCycleComplete, if non-nil, will be closed when the next block is committed
var FirstCycleComplete chan struct{}

// DoInit creates the necessary files to create a new tendermint chain
func DoInit(config *cfg.Config, logger tmlog.Logger) error {
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
		key, err := pv.GetPubKey()
		if err != nil {
			return errors.Wrap(err, "failed to retrieve public key")
		}
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

type tendermintFullNode struct {
	config *cfg.Config
	logger tmlog.Logger
	app    abcitypes.Application
	dbopt  *badger.Options

	db   *badger.DB
	node *nm.Node
}

func (node *tendermintFullNode) readAppConfig(configFile string) error {
	// read config
	node.config.RootDir = filepath.Dir(filepath.Dir(configFile))
	viper.SetConfigFile(configFile)
	if err := viper.ReadInConfig(); err != nil {
		return errors.Wrap(err, "viper failed to read config file")
	}
	if err := viper.Unmarshal(node.config); err != nil {
		return errors.Wrap(err, "viper failed to unmarshal config")
	}
	if err := node.config.ValidateBasic(); err != nil {
		return errors.Wrap(err, "config is invalid")
	}

	// create logger
	var err error
	node.logger, err = tmflags.ParseLogLevel(node.config.LogLevel, node.logger, cfg.DefaultLogLevel())
	if err != nil {
		return errors.Wrap(err, "failed to parse log level")
	}

	return nil
}

func (node *tendermintFullNode) instantiateApp() error {

	// read private validator
	pv := privval.LoadFilePV(
		node.config.PrivValidatorKeyFile(),
		node.config.PrivValidatorStateFile(),
	)

	// read node key
	nodeKey, err := p2p.LoadNodeKey(node.config.NodeKeyFile())
	if err != nil {
		return errors.Wrap(err, "failed to load node's key")
	}

	// create node
	node.node, err = nm.NewNode(
		node.config,
		pv,
		nodeKey,
		proxy.NewLocalClientCreator(node.app),
		nm.DefaultGenesisDocProviderFunc(node.config),
		nm.DefaultDBProvider,
		nm.DefaultMetricsProvider(node.config.Instrumentation),
		node.logger)
	if err != nil {
		return errors.Wrap(err, "failed to create new Tendermint node")
	}

	return nil
}

func (node *tendermintFullNode) prepareNode() error {
	configFile := filepath.Join(filepath.Dir(node.config.NodeKeyFile()), "config.toml")

	flag.Parse()
	err := node.readAppConfig(configFile)
	if err != nil {
		return err
	}

	dbPath := filepath.Join(filepath.Dir(node.config.PrivValidatorStateFile()), "store.db")
	dbopt := badger.DefaultOptions(dbPath)
	node.dbopt = &dbopt
	badgerLogger := newBadgerLogger(node.logger)
	node.dbopt.Logger = badgerLogger
	if strings.HasPrefix(runtime.GOOS, "windows") {
		dbopt = node.dbopt.WithTruncate(true)
		node.dbopt = &dbopt
	}
	node.app = NewAthenaStoreApplication(nil, node.logger)

	err = node.instantiateApp()

	return err
}

func (node *tendermintFullNode) Start(ctx context.Context) error {
	var err error
	node.db, err = badger.Open(*node.dbopt)
	if err != nil {
		return errors.Wrap(err, "failed to open badger db")
	}
	node.app.(*AthenaStoreApplication).db = node.db

	err = node.node.Start()
	if err != nil {
		return errors.Wrap(err, "failed to launch tendermint node")
	}

	return nil
}

func (node *tendermintFullNode) Stop(ctx context.Context) (err error) {

	if node.node != nil {
		err = node.node.Stop()
		node.node.Wait()
		node.node = nil
	}

	if node.db != nil {
		err2 := node.db.Close()
		if err2 != nil {
			err = err2
		}
		node.db = nil
	}

	return
}

// NewFullNode creates and returns a tendermint node (implementing Service)
func NewFullNode(config *cfg.Config, logger tmlog.Logger) (common.Service, error) {
	node := &tendermintFullNode{
		config: config,
		logger: logger,
	}
	err := node.prepareNode()
	if err != nil {
		return nil, err
	}
	return node, nil
}
