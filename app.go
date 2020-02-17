package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"strings"

	"github.com/dgraph-io/badger"
	abcitypes "github.com/tendermint/tendermint/abci/types"
)

// AthenaStoreApplication defines our blockchain application and its behavior
type AthenaStoreApplication struct {
	db           *badger.DB
	currentBatch *badger.Txn
}

type athenaTx struct {
	Pkey []byte
	Sign []byte
	Msg  map[string]interface{}
}

const (
	// ERR_Ok no error
	ERR_Ok = iota
	// ERR_TxTooShort the transaction does not include the minimum pk + signature
	ERR_TxTooShort
	// ERR_TxBadJson the body of the transaction is not well-formed
	ERR_TxBadJson
	// ERR_TxBadSign the signature of this transaction does not match the PKey
	ERR_TxBadSign
)

var _ abcitypes.Application = (*AthenaStoreApplication)(nil)

// NewAthenaStoreApplication create a new instance of AthenaStoreApplication
func NewAthenaStoreApplication() *AthenaStoreApplication {
	return &AthenaStoreApplication{}
}

func (app *AthenaStoreApplication) unpackTx(tx []byte) (*athenaTx, uint32, string) {
	dec := athenaTx{}
	if len(tx) < 96 {
		return nil, ERR_TxTooShort, "Tx too short"
	}
	dec.Pkey = tx[0:32]
	dec.Sign = tx[32:96]

	body := tx[96:]
	if !ed25519.Verify(dec.Pkey, body, dec.Sign) {
		return nil, ERR_TxBadSign, "Transaction signature invalid"
	}

	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.UseNumber()
	var json interface{}
	if err := decoder.Decode(&json); err != nil {
		return nil, ERR_TxBadJson, err.Error()
	}
	var ok bool
	if dec.Msg, ok = json.(map[string]interface{}); !ok {
		return nil, ERR_TxBadJson, "Transaction must not be a JSON literal"
	}

	return &dec, ERR_Ok, ""
}

func (app *AthenaStoreApplication) isValid(tx *athenaTx) (code uint32, codeContext string, codeDescr string) {
	//key, value := parts[0], parts[1]

	// check if the same key=value already exists
	err := app.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(key)
		if err != nil && err != badger.ErrKeyNotFound {
			return err
		}
		if err == nil {
			return item.Value(func(val []byte) error {
				if bytes.Equal(val, value) {
					code = 2
					codeContext = "athena"
					codeDescr = "key already exists"
				}
				return nil
			})
		}
		return nil
	})
	if err != nil {
		return 2, "badger", err.Error()
	}

	return code, codeContext, codeDescr
}

// Info Return information about the application state
func (app *AthenaStoreApplication) Info(req abcitypes.RequestInfo) abcitypes.ResponseInfo {
	return abcitypes.ResponseInfo{}
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
	code, codeContext, info := app.isValid(tx)
	if code != 0 {
		return abcitypes.ResponseDeliverTx{Code: code, Codespace: codeContext, Info: info}
	}

	return abcitypes.ResponseDeliverTx{Code: 0}
}

// CheckTx (Optional) Guardian of the mempool: every node runs CheckTx before letting a transaction into its local mempool
func (app *AthenaStoreApplication) CheckTx(req abcitypes.RequestCheckTx) abcitypes.ResponseCheckTx {
	tx, code, info := app.unpackTx(req.Tx)
	if code != 0 {
		return abcitypes.ResponseCheckTx{Code: code, Codespace: "athena", Info: info}
	}
	code, codeContext, info := app.isValid(tx)
	if code != 0 {
		return abcitypes.ResponseCheckTx{Code: code, Codespace: codeContext, Info: info}
	}
	return abcitypes.ResponseCheckTx{Code: 0, GasWanted: 1}
}

// Commit Persist the application state. Later calls to Query can return proofs about the application state anchored in this Merkle root hash
func (app *AthenaStoreApplication) Commit() abcitypes.ResponseCommit {
	return abcitypes.ResponseCommit{}
}

// Query Query for data from the application at current or past height
func (app *AthenaStoreApplication) Query(req abcitypes.RequestQuery) abcitypes.ResponseQuery {
	return abcitypes.ResponseQuery{Code: 0}
}

// InitChain Called once upon genesis
func (app *AthenaStoreApplication) InitChain(req abcitypes.RequestInitChain) abcitypes.ResponseInitChain {
	return abcitypes.ResponseInitChain{}
}

// BeginBlock Signals the beginning of a new block. Called prior to any DeliverTxs
func (app *AthenaStoreApplication) BeginBlock(req abcitypes.RequestBeginBlock) abcitypes.ResponseBeginBlock {
	return abcitypes.ResponseBeginBlock{}
}

// EndBlock Signals the end of a block. Called after all transactions, prior to each Commit
func (app *AthenaStoreApplication) EndBlock(req abcitypes.RequestEndBlock) abcitypes.ResponseEndBlock {
	return abcitypes.ResponseEndBlock{}
}
