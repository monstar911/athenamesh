package app

// Holds the logic in the ABCI application to actually authenticate the user and complete any query or alter commands

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"

	"github.com/dgraph-io/badger"
)

type permissionPathEntry struct {
	PathPat *regexp.Regexp
	IsAuth  bool
}

var permPaths = map[string]*permissionPathEntry{
	"all":             &permissionPathEntry{regexp.MustCompile(".*"), false},
	"userPrefix":      &permissionPathEntry{regexp.MustCompile("^(user/[^/]+)/"), false},
	"userAuth":        &permissionPathEntry{regexp.MustCompile("^(user/([^/]+))/auth$"), true},
	"userPrivStore":   &permissionPathEntry{regexp.MustCompile("^(user/[^/]+)/privStore"), false},
	"userStore":       &permissionPathEntry{regexp.MustCompile("^(user/[^/]+)/store"), false},
	"loginAuth":       &permissionPathEntry{regexp.MustCompile("^(user/[^/]+)/login/[^/]+/auth$"), true},
	"domainAuth":      &permissionPathEntry{regexp.MustCompile("^(user/[^/]+)/domain/[^/]+/auth$"), true},
	"domainPrivStore": &permissionPathEntry{regexp.MustCompile("^(user/[^/]+)/domain/[^/]+/privStore"), false},
	"domainStore":     &permissionPathEntry{regexp.MustCompile("^(user/[^/]+)/domain/[^/]+/store"), false},
	"domainLoc":       &permissionPathEntry{regexp.MustCompile("^(user/[^/]+)/domain/[^/]+/loc"), false},
}

type permissionMapEntry struct {
	PathPat  string
	UserType *userTypeConfig
	CanWrite bool
}

var permissions = []permissionMapEntry{
	permissionMapEntry{"all", rootUserTypeConfig, true},
	permissionMapEntry{"userPrefix", userUserTypeConfig, false},
	permissionMapEntry{"userAuth", userUserTypeConfig, true},
	permissionMapEntry{"userPrivStore", userUserTypeConfig, true},
	permissionMapEntry{"userPrivStore", loginUserTypeConfig, true},
	permissionMapEntry{"userStore", nil, false},
	permissionMapEntry{"userStore", userUserTypeConfig, true},
	permissionMapEntry{"userStore", loginUserTypeConfig, true},
	permissionMapEntry{"loginAuth", loginUserTypeConfig, true},
	permissionMapEntry{"domainAuth", loginUserTypeConfig, true},
	permissionMapEntry{"domainPrivStore", loginUserTypeConfig, true},
	permissionMapEntry{"domainPrivStore", domainUserTypeConfig, true},
	permissionMapEntry{"domainStore", nil, false},
	permissionMapEntry{"domainStore", loginUserTypeConfig, true},
	permissionMapEntry{"domainStore", domainUserTypeConfig, true},
	permissionMapEntry{"domainLoc", nil, false},
	permissionMapEntry{"domainLoc", loginUserTypeConfig, true},
	permissionMapEntry{"domainLoc", domainUserTypeConfig, true},
}

func verifySignature(pubKey []byte, message []byte, sig []byte) bool {
	if len(pubKey) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pubKey, message, sig)
}

func (app *AthenaStoreApplication) isAuth(tx *athenaTx) (*loginEntry, error) {

	if tx.Pkey == nil || tx.Sign == nil {
		return nil, nil // no authentication provided
	}
	var login *loginEntry = nil

	// Intentionally calling app.db.View rather than using any uncommitted transaction -- we want committed values here
	err := app.db.View(func(txn *badger.Txn) error {
		keyQuery := "keymap/" + base64.RawURLEncoding.EncodeToString(tx.Pkey)
		gKeyPath, err := GetBadgerVal(txn, keyQuery)
		if err != nil {
			return err // error or no key found
		}
		if gKeyPath == nil {
			return nil // no key found
		}

		keyPath, ok := gKeyPath.(string)
		if !ok {
			return fmt.Errorf("Unexpected key path %v while fetching from %s", gKeyPath, keyQuery)
		}

		var parentPath string
		login, parentPath = domainUserTypes.MatchFromPath(keyPath)
		if login == nil {
			return fmt.Errorf("Unsupported key path %s while fetching from %s", keyPath, keyQuery)
		}

		err = login.queryAccountData(txn, keyPath, keyQuery)
		if err != nil {
			return err
		}

		if len(login.Pubkey) == 0 {
			return fmt.Errorf("Missing key path %s while fetching from %s", keyPath, keyQuery)
		}
		if !bytes.Equal(login.Pubkey, tx.Pkey) {
			return fmt.Errorf("Pubkey mismatch: requested %s but resolved to %s",
				base64.RawURLEncoding.EncodeToString(tx.Pkey),
				base64.RawURLEncoding.EncodeToString(login.Pubkey))
		}

		if parentPath != "" {
			if len(login.ParentSign) == 0 {
				return errors.New("Account is a child object but is missing a signature")
			}

			parentLogin, _ := domainUserTypes.MatchFromPath(parentPath)
			if parentLogin == nil {
				return fmt.Errorf("Unsupported parent key path %s", parentPath)
			}

			login.Parent = parentLogin
			err = parentLogin.queryAccountData(txn, parentPath, keyPath)
			if err != nil {
				return err
			}

			if len(parentLogin.Pubkey) == 0 {
				return fmt.Errorf("Account object %s/auth missing pubKey", parentPath)
			}
			if !verifySignature(parentLogin.Pubkey, tx.Pkey, login.ParentSign) {
				return errors.New("Account is a child object but its signature was failed by its parent")
			}

			return nil
		}
		return nil
	})
	return login, err
}

func (app *AthenaStoreApplication) createRootUser(txn *badger.Txn, pubkey []byte) error {
	login := &loginEntry{
		Type:   rootUserTypeConfig,
		Pubkey: pubkey,
	}
	path := login.path()
	if path == "" || login.Parent != nil {
		return errors.New("Attempt to create an invalid user")
	}

	acctPath := path + "/auth"
	gAcctData, err := GetBadgerVal(txn, acctPath)
	if err != nil {
		return err
	}
	if gAcctData != nil {
		return errors.New("Account already exists")
	}

	newAcctData := login.assembleAccountData()
	return app.setKey(txn, acctPath, newAcctData)
}

func (app *AthenaStoreApplication) canAccess(forWrite bool, login *loginEntry, path string) (isGranted bool, isAuthPath bool) {
	prefixCache := make(map[string][]string)
	matchPrefix := ""

	for _, perm := range permissions {
		if login.Type != perm.UserType || (forWrite && !perm.CanWrite) {
			// not intended for our user type or it's r/o, so skip
			continue
		}
		permPath := permPaths[perm.PathPat]
		if _, ok := prefixCache[perm.PathPat]; !ok {
			prefixCache[perm.PathPat] = permPath.PathPat.FindStringSubmatch(path)
		}
		matches := prefixCache[perm.PathPat]
		if matches == nil {
			continue
		}
		if len(matches) <= 1 {
			// this pattern matches with no qualifiers, accept it and go
			isGranted = true
			if permPath.IsAuth {
				isAuthPath = true
			}
		}
		if matchPrefix == "" {
			// the permission is asking for a matching user, might as well figure out what ours is
			apexEntry := login
			if apexEntry.Parent != nil {
				apexEntry = apexEntry.Parent
			}
			matchPrefix = apexEntry.path()
		}
		if matches[1] == matchPrefix {
			isGranted = true
			if permPath.IsAuth {
				isAuthPath = true
			}
		}
	}
	return
}

func (app *AthenaStoreApplication) isValid(tx *athenaTx, msg map[string]interface{}, login *loginEntry) (code uint32, codeDescr string) {
	for key, value := range msg {
		if login != nil {
			canAccess, _ := app.canAccess(true, login, key)
			if !canAccess {
				return ErrorUnauth, fmt.Sprintf("Not authorized to write to %s", key)
			}
		} else if tx.Pkey == nil || tx.Sign == nil {
			return ErrorTxBadSign, "Transactions require a valid signature to be present"
		} else if valueAsMap, ok := value.(map[string]interface{}); ok {
			canAccess := false

			// we need to special-case users creating a new user account, which would appear as a self-signed write to a nonexistent userAuth location
			userAuthPath := permPaths["userAuth"].PathPat.FindStringSubmatch(key)
			if userAuthPath != nil {
				// attempt to decode the value into a login Entry
				reqAcctData := &loginEntry{Type: userUserTypeConfig}
				err := reqAcctData.decodeAccountData(valueAsMap, key, true)
				if err == nil && reqAcctData.Name != "" && bytes.Equal(reqAcctData.Pubkey, tx.Pkey) {
					// okay this is properly self-signed, if the user doesn't exist then we'll consider this a valid createUser request
					if gAcctData, err := GetBadgerVal(app.currentBatch, key); gAcctData != nil && err == nil {
						return ErrorUnauth, fmt.Sprintf("User %s already exists", userAuthPath[2])
					}
					canAccess = true
				}
			}
			if !canAccess {
				return ErrorUnknownUser, fmt.Sprintf("Did not recognize key %s", base64.RawURLEncoding.EncodeToString(tx.Pkey))
			}
		}
	}
	return 0, ""
}

func (app *AthenaStoreApplication) executeTx(tx *athenaTx, msg map[string]interface{}, login *loginEntry) (code uint32, codeDescr string) {
	for key, value := range msg {
		if login != nil {
			canAccess, isAuthPath := app.canAccess(true, login, key)
			if !canAccess {
				return ErrorUnauth, fmt.Sprintf("Not authorized to write to %s", key)
			}
			if isAuthPath {
				reqAcctData, _ := domainUserTypes.MatchFromPath(key)
				if reqAcctData == nil {
					return ErrorUnexpected, fmt.Sprintf("we're told that %s is an auth keypath but cannot resolve the token type?", key)
				}

				// retrieve the existing auth token (if there is one)
				if gAcctData, err := GetBadgerVal(app.currentBatch, key); gAcctData != nil && err == nil {
					acctData, ok := gAcctData.(map[string]interface{})
					if ok {
						err = reqAcctData.decodeAccountData(acctData, key, false)
					}
				}
				// clean up the retrieved login information
				reqAcctData.Attrs = make(map[string]interface{})
				if reqAcctData.Created == 0 {
					reqAcctData.Created = app.treeState.lastBlockHeight + 1
				}

				// import the new auth data into this token
				acctData, ok := value.(map[string]interface{})
				if !ok {
					return ErrorBadFormat, fmt.Sprintf("Attempt to change %s which is an auth key but the value is not a map", key)
				}
				err := reqAcctData.decodeAccountData(acctData, key, true)
				if err != nil {
					return ErrorBadFormat, err.Error()
				}
				if reqAcctData.Parent != nil {
					parentLogin := reqAcctData.Parent
					parentPath := parentLogin.path()
					err := parentLogin.queryAccountData(app.currentBatch, parentPath, parentPath)
					if err != nil {
						return ErrorBadFormat, err.Error()
					}
					if len(parentLogin.Pubkey) == 0 {
						return ErrorBadFormat, fmt.Sprintf("Account object %s/auth missing pubKey", parentPath)
					}
					if !verifySignature(parentLogin.Pubkey, reqAcctData.Pubkey, reqAcctData.ParentSign) {
						return ErrorBadFormat, "Account is a child object but its signature was failed by its parent"
					}
				}

				// write it back out as a new value
				value = reqAcctData.assembleAccountData()
			}
		} else if tx.Pkey == nil || tx.Sign == nil {
			return ErrorTxBadSign, "Transactions require a valid signature to be present"
		} else if valueAsMap, ok := value.(map[string]interface{}); ok {
			// we need to special-case users creating a new user account, which would appear as a self-signed write to a nonexistent userAuth location
			canAccess := false
			userAuthPath := permPaths["userAuth"].PathPat.FindStringSubmatch(key)
			if userAuthPath != nil {
				// attempt to decode the value into a login Entry
				reqAcctData := &loginEntry{
					Type:    userUserTypeConfig,
					Created: app.treeState.lastBlockHeight + 1,
				}
				err := reqAcctData.decodeAccountData(valueAsMap, key, true)
				if err == nil && reqAcctData.Name != "" && bytes.Equal(reqAcctData.Pubkey, tx.Pkey) {
					// okay this is properly self-signed, if the user doesn't exist then we'll consider this a valid createUser request
					if gAcctData, err := GetBadgerVal(app.currentBatch, key); gAcctData != nil && err == nil {
						return ErrorUnauth, fmt.Sprintf("User %s already exists", userAuthPath[2])
					}
					canAccess = true
					value = reqAcctData.assembleAccountData()
				}
			}
			if !canAccess {
				return ErrorUnknownUser, fmt.Sprintf("Did not recognize key %s", base64.RawURLEncoding.EncodeToString(tx.Pkey))
			}
		}
		err := app.setKey(app.currentBatch, key, value)
		if err != nil {
			return ErrorUnexpected, err.Error()
		}
	}
	return 0, ""
}

func (app *AthenaStoreApplication) doQuery(tx *athenaTx, key string, login *loginEntry) (code uint32, codeDescr string, response interface{}) {
	if login != nil {
		canAccess, isAuthPath := app.canAccess(false, login, key)
		if !canAccess {
			return ErrorUnauth, fmt.Sprintf("Not authorized to read from %s", key), nil
		}
		if isAuthPath {
			reqAcctData, _ := domainUserTypes.MatchFromPath(key)
			if reqAcctData == nil {
				return ErrorUnexpected, fmt.Sprintf("we're told that %s is an auth keypath but cannot resolve the token type?", key), nil
			}

			// retrieve the existing auth token (if there is one)
			gAcctData, err := GetBadgerVal(app.currentBatch, key)
			if err != nil {
				return ErrorUnexpected, err.Error(), nil
			}
			if gAcctData == nil {
				return ErrorOk, "", nil // no key value
			}
			acctData, ok := gAcctData.(map[string]interface{})
			if !ok {
				return ErrorUnexpected, fmt.Sprintf("Unexpected account object while fetching from %s", key), nil
			}
			err = reqAcctData.decodeAccountData(acctData, key, false)
			if err != nil {
				return ErrorUnexpected, err.Error(), nil
			}

			// write it back out as a new value
			return ErrorOk, "", reqAcctData.assembleQueryData()
		}

		// okay, this is a standard query that we are pemitted to retrieve
		result, err := GetBadgerVal(app.currentBatch, key)
		if err != nil {
			return ErrorUnexpected, err.Error(), nil
		}
		return ErrorOk, "", result

	} else if tx.Pkey == nil || tx.Sign == nil {
		// we need to special-case users querying user account properties when trying to login
		userAuthPath := permPaths["userAuth"].PathPat.FindStringSubmatch(key)
		if userAuthPath == nil {
			return ErrorUnauth, fmt.Sprintf("Query of %s requires a valid user", key), nil
		}

		reqAcctData, _ := domainUserTypes.MatchFromPath(key)
		if reqAcctData == nil {
			return ErrorUnexpected, fmt.Sprintf("we're told that %s is an auth keypath but cannot resolve the token type?", key), nil
		}

		// retrieve the existing auth token (if there is one)
		gAcctData, err := GetBadgerVal(app.currentBatch, key)
		if err != nil {
			return ErrorUnexpected, err.Error(), nil
		}
		if gAcctData == nil {
			return ErrorOk, "", nil // no key value
		}
		acctData, ok := gAcctData.(map[string]interface{})
		if !ok {
			return ErrorUnexpected, fmt.Sprintf("Unexpected account object while fetching from %s", key), nil
		}
		err = reqAcctData.decodeAccountData(acctData, key, false)
		if err != nil {
			return ErrorUnexpected, err.Error(), nil
		}

		// unauthenticated users can only retrieve the extended information
		return ErrorOk, "", reqAcctData.Attrs
	}
	return ErrorUnknownUser, fmt.Sprintf("Did not recognize key %s", base64.RawURLEncoding.EncodeToString(tx.Pkey)), nil
}
