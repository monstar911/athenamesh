package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/dgraph-io/badger"
)

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
