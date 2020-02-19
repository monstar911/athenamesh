package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/dgraph-io/badger"
	abcitypes "github.com/tendermint/tendermint/abci/types"
)

type treeStateData struct {
	lastBlockHeight int64
	lastBlockHash   []byte
}

type userTypeConfig struct {
	UsePassphrase bool
	IsAuthorized  bool
	PathPat       *regexp.Regexp
}

var adminUserTypeConfig = &userTypeConfig{
	UsePassphrase: false,
	IsAuthorized:  true,
	PathPat:       regexp.MustCompile("^config/rootUser$"),
}

var userUserTypeConfig = &userTypeConfig{
	UsePassphrase: true,
	IsAuthorized:  true,
	PathPat:       regexp.MustCompile("^user/[^/]+$"),
}

var loginUserTypeConfig = &userTypeConfig{
	UsePassphrase: false,
	PathPat:       regexp.MustCompile("^(user/[^/]+)/login/[^/]+$"),
}

var domainUserTypeConfig = &userTypeConfig{
	UsePassphrase: false,
	PathPat:       regexp.MustCompile("^(user/[^/]+)/domain/[^/]+$"),
}

type domainUserTypeStore struct {
	userTypes []*userTypeConfig
}

var domainUserTypes = &domainUserTypeStore{
	userTypes: []*userTypeConfig{adminUserTypeConfig, userUserTypeConfig, loginUserTypeConfig, domainUserTypeConfig},
}

func (app *domainUserTypeStore) MatchFromPath(path string) (*userTypeConfig, string) {
	for _, typ := range app.userTypes {
		matches := typ.PathPat.FindStringSubmatch(path)
		if matches != nil {
			parentPath := ""
			if len(matches) > 1 {
				parentPath = matches[1]
			}
			return typ, parentPath
		}
	}
	return nil, ""
}

// AthenaStoreApplication defines our blockchain application and its behavior
type AthenaStoreApplication struct {
	db           *badger.DB
	currentBatch *badger.Txn
	treeState    treeStateData
}

type athenaTx struct {
	Pkey []byte
	Sign []byte
	Msg  map[string]interface{}
}

const (
	// ErrorOk no error
	ErrorOk = iota
	// ErrorTxTooShort the transaction does not include the minimum pk + signature
	ErrorTxTooShort
	// ErrorTxBadJSON the body of the transaction is not well-formed
	ErrorTxBadJSON
	// ErrorTxBadSign the signature of this transaction does not match the PKey
	ErrorTxBadSign
	// ErrorUnexpected an unexpected condition was encountered
	ErrorUnexpected
	// ErrorUnknownUser did not recognize the public key
	ErrorUnknownUser
)

var _ abcitypes.Application = (*AthenaStoreApplication)(nil)

// NewAthenaStoreApplication create a new instance of AthenaStoreApplication
func NewAthenaStoreApplication(db *badger.DB) *AthenaStoreApplication {
	app := &AthenaStoreApplication{db: db}
	app.init()
	return app
}

func (app *AthenaStoreApplication) loadTreeState() error {
	// load our current status
	return app.db.View(func(txn *badger.Txn) error {
		val, err := GetBadgerTree(txn, "!")
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

func (app *AthenaStoreApplication) unpackTx(tx []byte) (*athenaTx, uint32, string) {
	dec := athenaTx{}
	if len(tx) < 96 {
		return nil, ErrorTxTooShort, "Tx too short"
	}
	dec.Pkey = tx[0:32]
	dec.Sign = tx[32:96]

	body := tx[96:]
	if !ed25519.Verify(dec.Pkey, body, dec.Sign) {
		return nil, ErrorTxBadSign, "Transaction signature invalid"
	}

	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.UseNumber()
	var json interface{}
	if err := decoder.Decode(&json); err != nil {
		return nil, ErrorTxBadJSON, err.Error()
	}
	var ok bool
	if dec.Msg, ok = json.(map[string]interface{}); !ok {
		return nil, ErrorTxBadJSON, "Transaction must not be a JSON literal"
	}

	return &dec, ErrorOk, ""
}

func (app *AthenaStoreApplication) isAuth(tx *athenaTx) (*userTypeConfig, map[string]interface{}, uint32, string) {

	var resultUserType *userTypeConfig
	var resultUserAuth map[string]interface{}

	err := app.db.View(func(txn *badger.Txn) error {
		keyQuery := "keys/" + base64.RawStdEncoding.EncodeToString(tx.Pkey)
		gKeyPath, err := GetBadgerVal(txn, keyQuery)
		if err != nil || gKeyPath == nil {
			return err // error or no key found
		}

		keyPath, ok := gKeyPath.(string)
		if !ok {
			return fmt.Errorf("Unexpected key path %v while fetching from %s", gKeyPath, keyQuery)
		}

		userType, parentPath := domainUserTypes.MatchFromPath(keyPath)
		if userType == nil {
			return fmt.Errorf("Unsupported key path %s while fetching from %s", keyPath, keyQuery)
		}

		acctPath := keyPath + "/auth"
		var gAcctData interface{}
		gAcctData, err = GetBadgerTree(txn, acctPath)
		if err != nil || gAcctData == nil {
			return fmt.Errorf("Missing key path %s while fetching from %s", acctPath, keyQuery)
		}
		var acctData map[string]interface{}
		acctData, ok = gAcctData.(map[string]interface{})
		if !ok {
			return fmt.Errorf("Unexpected account object %v while fetching from %s", gAcctData, acctPath)
		}
		var gPubKey interface{}
		gPubKey, ok = acctData["pubKey"]
		if !ok {
			return fmt.Errorf("Account object %s missing pubKey", acctPath)
		}
		var pubKey string
		pubKey, ok = gPubKey.(string)
		if !ok {
			return fmt.Errorf("Found unexpected non-string %v reading %s/pubKey", gPubKey, acctPath)
		}
		if pubKey != string(tx.Pkey) {
			return fmt.Errorf("Pubkey mismatch: requested %s but resolved to %s",
				base64.RawStdEncoding.EncodeToString(tx.Pkey),
				base64.RawStdEncoding.EncodeToString([]byte(pubKey)))
		}

		if parentPath != "" {
			var gParentSign interface{}
			gParentSign, ok = acctData["sign"]
			if !ok {
				return errors.New("Account is a child object but is missing a signature")
			}
			var parentSign string
			parentSign, ok = gParentSign.(string)
			if !ok {
				return fmt.Errorf("Found unexpected non-string %v reading %s/sign", gParentSign, acctPath)
			}

			parentUserType, _ := domainUserTypes.MatchFromPath(parentPath)
			if parentUserType == nil {
				return fmt.Errorf("Unsupported parent key path %s", parentPath)
			}

			parentAcctPath := parentPath + "/auth"
			var gParentAcctData interface{}
			gParentAcctData, err = GetBadgerTree(txn, parentAcctPath)
			if err != nil || gParentAcctData == nil {
				return fmt.Errorf("Missing key path %s while fetching from %s", parentAcctPath, parentAcctPath)
			}
			var parentAcctData map[string]interface{}
			parentAcctData, ok = gParentAcctData.(map[string]interface{})
			if !ok {
				return fmt.Errorf("Unexpected account object %v while fetching from %s", gParentAcctData, parentAcctPath)
			}
			var gParentPubKey interface{}
			gParentPubKey, ok = parentAcctData["pubKey"]
			if !ok {
				return fmt.Errorf("Account object %s missing pubKey", parentAcctPath)
			}
			var parentPubKey string
			parentPubKey, ok = gParentPubKey.(string)
			if !ok {
				return fmt.Errorf("Found unexpected non-string %v reading %s/pubKey", gParentPubKey, parentAcctPath)
			}
			if !ed25519.Verify([]byte(parentPubKey), tx.Pkey, []byte(parentSign)) {
				return errors.New("Account is a child object but its signature was failed by its parent")
			}

			resultUserType = parentUserType
			resultUserAuth = parentAcctData
			return nil
		}

		resultUserType = userType
		resultUserAuth = acctData
		return nil
	})
	if err != nil {
		return nil, nil, ErrorUnexpected, err.Error()
	}
	if resultUserType == nil {
		return nil, nil, ErrorUnknownUser, fmt.Sprintf("Did not recognize key %s", base64.RawStdEncoding.EncodeToString(tx.Pkey))
	}
	return resultUserType, resultUserAuth, 0, ""
}

func (app *AthenaStoreApplication) isValid(tx *athenaTx, user *userTypeConfig, userData map[string]interface{}) (code uint32, codeDescr string) {
	//key, value := parts[0], parts[1]

	// check if the same key=value already exists
	/*	err := app.db.View(func(txn *badger.Txn) error {
			item, err := txn.Get(key)
			if err != nil && err != badger.ErrKeyNotFound {
				return err
			}
			if err == nil {
				return item.Value(func(val []byte) error {
					if bytes.Equal(val, value) {
						code = 2
						codeDescr = "key already exists"
					}
					return nil
				})
			}
			return nil
		})
		if err != nil {
			return 2, err.Error()
		}

		return code, codeDescr*/
	return 0, ""
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
	user, userData, code, info := app.isAuth(tx)
	if code != 0 {
		return abcitypes.ResponseDeliverTx{Code: code, Codespace: "athena", Info: info}
	}
	code, info = app.isValid(tx, user, userData)
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
	user, userData, code, info := app.isAuth(tx)
	if code != 0 {
		return abcitypes.ResponseCheckTx{Code: code, Codespace: "athena", Info: info}
	}
	code, info = app.isValid(tx, user, userData)
	if code != 0 {
		return abcitypes.ResponseCheckTx{Code: code, Codespace: "athena", Info: info}
	}
	return abcitypes.ResponseCheckTx{Code: 0}
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
