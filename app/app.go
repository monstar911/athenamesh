package app

// Implements the ABCI interface required to communicate with Tendermint

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/dgraph-io/badger"
	abcitypes "github.com/tendermint/tendermint/abci/types"
	tmlog "github.com/tendermint/tendermint/libs/log"
)

type treeStateData struct {
	lastBlockHeight int64
	nextBlockHeight int64
	lastBlockHash   []byte
}

// AthenaStoreApplication defines our blockchain application and its behavior
type AthenaStoreApplication struct {
	db               *badger.DB
	logger           tmlog.Logger
	currentBatch     *badger.Txn
	treeState        treeStateData
	singleBlockEvent chan<- struct{}
}

type athenaTx struct {
	Pkey []byte
	Sign []byte
	Msg  interface{}
}

const (
	// ErrorOk no error
	ErrorOk = iota
	// ErrorTxTooShort the transaction does not include the minimum pk + signature
	ErrorTxTooShort
	// ErrorTxBadSign the signature of this transaction does not match the PKey
	ErrorTxBadSign
	// ErrorUnexpected an unexpected condition was encountered
	ErrorUnexpected
	// ErrorUnknownUser did not recognize the public key
	ErrorUnknownUser
	// ErrorUnauth does not have permission to do the requested action
	ErrorUnauth
	// ErrorBadFormat has a request that is not readable
	ErrorBadFormat
)

var _ abcitypes.Application = (*AthenaStoreApplication)(nil)

// NewAthenaStoreApplication create a new instance of AthenaStoreApplication
func NewAthenaStoreApplication(db *badger.DB, logger tmlog.Logger) *AthenaStoreApplication {
	app := &AthenaStoreApplication{db: db, logger: logger}
	app.init()
	return app
}

// InitChain Called once upon genesis
func (app *AthenaStoreApplication) InitChain(req abcitypes.RequestInitChain) abcitypes.ResponseInitChain {
	// create the root user
	pubb, pvk, _ := ed25519.GenerateKey(nil)
	err := app.db.Update(func(txn *badger.Txn) error {
		err := app.createRootUser(txn, pubb)
		if err != nil {
			return err
		}

		// store the genesis parameters so we can regenerate them
		genTime, err := req.Time.GobEncode()
		if err != nil {
			return err
		}
		err = app.setKey(txn, "mesh/genesis/time", genTime)
		if err != nil {
			return err
		}
		err = app.setKey(txn, "mesh/genesis/chain_id", req.ChainId)
		if err != nil {
			return err
		}

		// assemble an object describing consensus_parameters
		srcConsensus := req.ConsensusParams
		var consBlock = map[string]interface{}{
			"MaxBytes": srcConsensus.Block.MaxBytes,
			"MaxGas":   srcConsensus.Block.MaxGas,
		}
		var consEvidence = map[string]interface{}{
			"MaxAgeNumBlocks": srcConsensus.Evidence.MaxAgeNumBlocks,
			"MaxAgeDuration":  int64(srcConsensus.Evidence.MaxAgeDuration),
		}
		var consValidator = map[string]interface{}{
			"PubKeyTypes": srcConsensus.Validator.PubKeyTypes,
		}
		var consensus = map[string]interface{}{"Block": consBlock, "Evidence": consEvidence, "Validator": consValidator}
		err = app.setKey(txn, "mesh/genesis/consensus_params", consensus)
		if err != nil {
			return err
		}

		// assemble an object describing Validators
		validators := make([]interface{}, len(req.Validators))
		for idx, val := range req.Validators {
			var pubKey = map[string]interface{}{"Type": val.PubKey.Type, "Data": val.PubKey.Data}
			var encVal = map[string]interface{}{"PubKey": pubKey, "Power": val.Power}
			validators[idx] = encVal
		}
		err = app.setKey(txn, "mesh/genesis/validators", consensus)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		app.logger.Error("Unexpected trying to initialize the chain: " + err.Error())
	}
	app.logger.Error("root user successfully created with key: " + base64.RawURLEncoding.EncodeToString(pvk))
	app.logger.Error("REMEMBER THIS KEY, it will not be recoverable again for this chain")

	return abcitypes.ResponseInitChain{}
}

func (app *AthenaStoreApplication) loadTreeState() error {
	// load our current status
	return app.db.View(func(txn *badger.Txn) error {
		val, err := GetBadgerVal(txn, "mesh/blockState")
		if err != nil {
			return err
		}
		if val == nil {
			// brand new KV store, use defaults
			return nil
		}
		if iVal, ok := val.(map[string]interface{}); ok {
			if lbh, ok := iVal["lastBlockHeight"]; ok {
				if iLbh, ok := NumberToInt64(lbh); ok {
					app.treeState.lastBlockHeight = iLbh
				} else {
					return fmt.Errorf("Unexpected lastBlockHeight querying the tree state: %v", lbh)
				}
			}
			if lbh, ok := iVal["lastBlockHash"]; ok {
				if bLbh, ok := lbh.([]byte); ok {
					app.treeState.lastBlockHash = bLbh
				} else {
					return fmt.Errorf("Unexpected lastBlockHash querying the tree state: %v", lbh)
				}
			}
			return nil
		}
		return fmt.Errorf("Unexpected value querying the tree state: %v", val)
	})
}

func (app *AthenaStoreApplication) init() {
	// load our current status
	err := app.loadTreeState()
	if err != nil {
		panic("Unexpected error on loading tree state: " + err.Error())
	}
}

// Info Return information about the application state
func (app *AthenaStoreApplication) Info(req abcitypes.RequestInfo) abcitypes.ResponseInfo {
	return abcitypes.ResponseInfo{
		LastBlockHeight:  app.treeState.lastBlockHeight,
		LastBlockAppHash: app.treeState.lastBlockHash,
	}
}

// BeginBlock Signals the beginning of a new block. Called prior to any DeliverTxs
func (app *AthenaStoreApplication) BeginBlock(req abcitypes.RequestBeginBlock) abcitypes.ResponseBeginBlock {
	if app.currentBatch != nil {
		app.logger.Error("Unexpected: calling BeginBlock with an open transaction (transaction discarded)")
	}
	app.currentBatch = app.db.NewTransaction(true)
	return abcitypes.ResponseBeginBlock{}
}

func (app *AthenaStoreApplication) unpackTx(tx []byte) (*athenaTx, uint32, string) {
	dec := athenaTx{}
	if len(tx) < 96 {
		return nil, ErrorTxTooShort, "Tx too short"
	}
	var body []byte
	if !bytes.Equal(tx[0:96], make([]byte, 96)) {
		dec.Pkey = tx[0:32]
		dec.Sign = tx[32:96]

		body = tx[96:]
		if !ed25519.Verify(dec.Pkey, body, dec.Sign) {
			return nil, ErrorTxBadSign, "Transaction signature invalid"
		}
	}

	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.UseNumber()
	if err := decoder.Decode(&dec.Msg); err != nil {
		return nil, ErrorBadFormat, err.Error()
	}

	return &dec, ErrorOk, ""
}

// SetOption Set non-consensus critical application specific options
func (app *AthenaStoreApplication) SetOption(req abcitypes.RequestSetOption) abcitypes.ResponseSetOption {
	return abcitypes.ResponseSetOption{}
}

// DeliverTx (Required) Execute the transaction in full
func (app *AthenaStoreApplication) DeliverTx(req abcitypes.RequestDeliverTx) abcitypes.ResponseDeliverTx {
	tx, code, info := app.unpackTx(req.Tx)
	if code != 0 {
		return abcitypes.ResponseDeliverTx{Code: code, Codespace: "athena", Info: info}
	}
	msg, ok := tx.Msg.(map[string]interface{})
	if !ok {
		return abcitypes.ResponseDeliverTx{Code: ErrorBadFormat, Codespace: "athena", Info: "Transactions must be a valid JSON object"}
	}
	user, err := app.isAuth(tx)
	if err != nil {
		return abcitypes.ResponseDeliverTx{Code: ErrorUnexpected, Codespace: "athena", Info: err.Error()}
	}
	code, info = app.isValid(tx, msg, user)
	if code != 0 {
		return abcitypes.ResponseDeliverTx{Code: code, Codespace: "athena", Info: info}
	}
	code, info = app.executeTx(tx, msg, user)
	if code != 0 {
		return abcitypes.ResponseDeliverTx{Code: code, Codespace: "athena", Info: info}
	}

	return abcitypes.ResponseDeliverTx{Code: 0}
}

// CheckTx (Optional) Guardian of the mempool: every node runs CheckTx before letting a transaction into its local mempool
func (app *AthenaStoreApplication) CheckTx(req abcitypes.RequestCheckTx) abcitypes.ResponseCheckTx {
	tx, code, info := app.unpackTx(req.Tx)
	if code != 0 {
		return abcitypes.ResponseCheckTx{Code: code, Codespace: "athena", Info: info}
	}
	msg, ok := tx.Msg.(map[string]interface{})
	if !ok {
		return abcitypes.ResponseCheckTx{Code: ErrorBadFormat, Codespace: "athena", Info: "Transactions must be a valid JSON object"}
	}
	user, err := app.isAuth(tx)
	if err != nil {
		return abcitypes.ResponseCheckTx{Code: ErrorUnexpected, Codespace: "athena", Info: err.Error()}
	}
	code, info = app.isValid(tx, msg, user)
	if code != 0 {
		return abcitypes.ResponseCheckTx{Code: code, Codespace: "athena", Info: info}
	}
	return abcitypes.ResponseCheckTx{Code: 0}
}

func (app *AthenaStoreApplication) updateLastBlockHeight(txn *badger.Txn) error {
	blockState := make(map[string]interface{})
	blockState["lastBlockHeight"] = app.treeState.nextBlockHeight

	encData, err := ToBadgerType(blockState)
	if err != nil {
		return err
	}
	return txn.Set([]byte("mesh/blockState"), encData)
}

// Query Query for data from the application at current or past height
func (app *AthenaStoreApplication) Query(req abcitypes.RequestQuery) abcitypes.ResponseQuery {
	tx, code, info := app.unpackTx(req.Data)
	if code != 0 {
		return abcitypes.ResponseQuery{Code: code, Codespace: "athena", Info: info}
	}
	user, err := app.isAuth(tx)
	if err != nil {
		return abcitypes.ResponseQuery{Code: ErrorUnexpected, Codespace: "athena", Info: err.Error()}
	}

	var response interface{}
	switch msg := tx.Msg.(type) {
	case string:
		code, info, response = app.doQuery(tx, msg, user)
	case []interface{}:
		result := make(map[string]interface{})
		var val interface{}
		for _, gKey := range msg {
			key, ok := gKey.(string)
			if !ok {
				return abcitypes.ResponseQuery{Code: ErrorBadFormat, Codespace: "athena", Info: "Queries must be a JSON string array or string literal"}
			}
			code, info, val = app.doQuery(tx, key, user)
			if code != 0 {
				return abcitypes.ResponseQuery{Code: code, Codespace: "athena", Info: info}
			}
			result[key] = val
		}
		response = result
	case []string:
		result := make(map[string]interface{})
		var val interface{}
		for _, key := range msg {
			code, info, val = app.doQuery(tx, key, user)
			if code != 0 {
				return abcitypes.ResponseQuery{Code: code, Codespace: "athena", Info: info}
			}
			result[key] = val
		}
		response = result
	default:
		return abcitypes.ResponseQuery{Code: ErrorBadFormat, Codespace: "athena", Info: "Queries must be a JSON string array or string literal"}
	}

	jsonValue, err := json.Marshal(response)
	if err != nil {
		return abcitypes.ResponseQuery{Code: ErrorUnexpected, Codespace: "athena", Info: err.Error()}
	}

	return abcitypes.ResponseQuery{Code: 0, Value: jsonValue}
}

// EndBlock Signals the end of a block. Called after all transactions, prior to each Commit
func (app *AthenaStoreApplication) EndBlock(req abcitypes.RequestEndBlock) abcitypes.ResponseEndBlock {
	app.treeState.nextBlockHeight = req.Height
	return abcitypes.ResponseEndBlock{}
}

// Commit Persist the application state. Later calls to Query can return proofs about the application state anchored in this Merkle root hash
func (app *AthenaStoreApplication) Commit() abcitypes.ResponseCommit {
	err := app.updateLastBlockHeight(app.currentBatch)
	if err != nil {
		app.logger.Error("Unexpected trying to update block state: " + err.Error())
	}

	app.currentBatch.Commit()
	app.currentBatch = nil
	if app.treeState.nextBlockHeight != 0 {
		app.treeState.lastBlockHeight = app.treeState.nextBlockHeight
		app.treeState.nextBlockHeight = 0
	}
	if app.singleBlockEvent != nil {
		close(app.singleBlockEvent)
		app.singleBlockEvent = nil
	}
	// if we're set to only run once then firstCycleComplete will be non-nil; signal that we've just completed a Commit
	if FirstCycleComplete != nil {
		close(FirstCycleComplete)
		FirstCycleComplete = nil
	}
	return abcitypes.ResponseCommit{}
}
