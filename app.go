package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
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
	Parent        *userTypeConfig
	PathPat       *regexp.Regexp
}

var adminUserTypeConfig = &userTypeConfig{
	UsePassphrase: false,
	PathPat:       regexp.MustCompile("^config/rootUser$"),
}

var userUserTypeConfig = &userTypeConfig{
	UsePassphrase: true,
	PathPat:       regexp.MustCompile("^user/[^/]+$"),
}

var loginUserTypeConfig = &userTypeConfig{
	UsePassphrase: false,
	Parent:        userUserTypeConfig,
	PathPat:       regexp.MustCompile("^(user/[^/]+)/login/[^/]+$"),
}

var domainUserTypeConfig = &userTypeConfig{
	UsePassphrase: false,
	Parent:        userUserTypeConfig,
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

/*
func (app *AthenaStoreApplication) loadConfig(txn *badger.Txn) (map[string]*userTypeConfig, error) {
	// (re-)load our operating configuration
	entry, err := GetBadgerTree(txn, "config/userTypes")
	if err != nil {
		return nil, err
	}
	if entry == nil {
		// brand new KV store.  This... doesn't seem to be the place to populate defaults, but we can't operate without it
		return nil, nil
	}
	if iEntry, ok := entry.(map[string]interface{}); ok {
		userTypes := make(map[string]*userTypeConfig)
		for key, val := range iEntry {
			if _, ok = userTypes[key]; ok {
				return nil, fmt.Errorf("unexpected duplicate user config %s", key)
			}
			if iVal, ok := val.(map[string]interface{}); ok {
				thisType := &userTypeConfig{}
				userTypes[key] = thisType
				if uPP, ok := iVal["usePassphrase"]; ok {
					if bUPP, ok := uPP.(bool); ok {
						thisType.UsePassphrase = bUPP
					} else {
						return nil, fmt.Errorf("Unexpected value querying user config %s.usePassphrase: %v", key, uPP)
					}
				}
				if parent, ok := iVal["parent"]; ok {
					if sParent, ok := parent.(string); ok {
						if sParentType, ok := userTypes[sParent]; ok {
							thisType.Parent = sParentType
						} else {
							return nil, fmt.Errorf("Could not locate parent type %s referenced in user config %s", sParent, key)
						}
					} else {
						return nil, fmt.Errorf("Unexpected value querying user config %s.parent: %v", key, parent)
					}
				}
			} else {
				return nil, fmt.Errorf("Unexpected value querying user config %s: %v", key, val)
			}
		}
		return userTypes, nil
	}
	return nil, fmt.Errorf("Unexpected value querying user config: %v", entry)
}

func storeDefaultConfigImpl(txn *badger.Txn, src map[string]interface{}, dest string) error {
	for key, val := range src {
		var err error = nil
		subkey := fmt.Sprintf("%s/%s", dest, key)
		switch v := val.(type) {
		case map[string]interface{}:
			err = storeDefaultConfigImpl(txn, v, subkey)
		default:
			var bval []byte
			bval, err = ToBadgerType(v)
			if err != nil {
				err = txn.Set([]byte(subkey), bval)
			}
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (app *AthenaStoreApplication) storeDefaultConfig() error {
	return app.db.Update(func(txn *badger.Txn) error {
		if config, ok := DefaultConfig.(map[string]interface{}); ok {
			return storeDefaultConfigImpl(txn, config, "config")
		}
		return fmt.Errorf("Unexpected value trying to store default configuration: %v", DefaultConfig)
	})
}
*/
func (app *AthenaStoreApplication) init() {
	// load our current status
	err := app.loadTreeState()
	if err != nil {
		panic("Unexpected error on loading tree state: " + err.Error())
	}
	/*var userTypes map[string]*userTypeConfig
	err = app.db.View(func(txn *badger.Txn) error {
		var err error
		userTypes, err = app.loadConfig(txn)
		return err
	})
	if err != nil {
		panic("Unexpected error on loading config: " + err.Error())
	}
	if userTypes == nil {
		err = app.storeDefaultConfig()
		if err != nil {
			panic("Unexpected error populating default config: " + err.Error())
		}
		err = app.db.View(func(txn *badger.Txn) error {
			var err error
			userTypes, err = app.loadConfig(txn)
			return err
		})
		if err != nil {
			panic("Unexpected error on loading config: " + err.Error())
		}
		if userTypes == nil {
			panic("Unable to populate default config")
		}
	}
	app.userConfig = userTypes*/
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

func (app *AthenaStoreApplication) isAuth(tx *athenaTx) (interface{}, uint32, string) {

	err := app.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(append([]byte("keys/"), []byte(base64.RawStdEncoding.EncodeToString(tx.Pkey))...))
		if err != nil {
			if err != badger.ErrKeyNotFound {
				return err // some error happened, just fail out now
			}
			return nil // no key found
		}
		keyPath := ""
		err = item.Value(func(v []byte) error {
			iVal, err := fromBadgerType(v)
			if err != nil {
				return err
			}
			if sVal, ok := iVal.(string); ok {
				keyPath = sVal
				return nil
			}
			return fmt.Errorf("Unexpected key path %v while fetching from keys/%s", iVal, base64.RawStdEncoding.EncodeToString(tx.Pkey))
		})
		if err != nil {
			return err
		}
		if keyPath == "" {
			return nil
		}

		userType, parentPath := domainUserTypes.MatchFromPath(keyPath)
		if userType == nil {
			return fmt.Errorf("Unsupported key path %s while fetching from keys/%s", keyPath, base64.RawStdEncoding.EncodeToString(tx.Pkey))
		}
		return nil
	})
	if err != nil {
		return nil, ErrorUnexpected, err.Error()
	}
	/*
		if keyPath == "" {
			return nil, ErrorUnknownUser, fmt.Sprintf("Did not recognize key %s", base64.RawStdEncoding.EncodeToString(tx.Pkey))
		}
	*/
	return nil, 0, ""
}

func (app *AthenaStoreApplication) isValid(tx *athenaTx, auth interface{}) (code uint32, codeDescr string) {
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
	auth, code, info := app.isAuth(tx)
	if code != 0 {
		return abcitypes.ResponseDeliverTx{Code: code, Codespace: "athena", Info: info}
	}
	code, info = app.isValid(tx, auth)
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
	auth, code, info := app.isAuth(tx)
	if code != 0 {
		return abcitypes.ResponseCheckTx{Code: code, Codespace: "athena", Info: info}
	}
	code, info = app.isValid(tx, auth)
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
