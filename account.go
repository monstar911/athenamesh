package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/dgraph-io/badger"
)

type userTypeConfig struct {
	UsePassphrase bool
	PathPat       *regexp.Regexp
}

var rootUserTypeConfig = &userTypeConfig{
	UsePassphrase: false,
	PathPat:       regexp.MustCompile("^()()config/rootUser$"),
}

var userUserTypeConfig = &userTypeConfig{
	UsePassphrase: true,
	PathPat:       regexp.MustCompile("^()user/([^/])+$"),
}

var loginUserTypeConfig = &userTypeConfig{
	UsePassphrase: false,
	PathPat:       regexp.MustCompile("^(user/[^/]+)/login/([^/])+$"),
}

var domainUserTypeConfig = &userTypeConfig{
	UsePassphrase: false,
	PathPat:       regexp.MustCompile("^(user/[^/]+)/domain/([^/])+$"),
}

type domainUserTypeStore struct {
	userTypes []*userTypeConfig
}

var domainUserTypes = &domainUserTypeStore{
	userTypes: []*userTypeConfig{rootUserTypeConfig, userUserTypeConfig, loginUserTypeConfig, domainUserTypeConfig},
}

type loginEntry struct {
	Type       *userTypeConfig
	Name       string
	Parent     *loginEntry
	Pubkey     string
	ParentSign string
}

func (login *loginEntry) path() string {
	switch login.Type {
	case rootUserTypeConfig:
		return "config/rootUser"
	case userUserTypeConfig:
		if strings.Contains(login.Name, "/") {
			return "" // name cannot contain slash
		}
		return "user/" + login.Name
	case loginUserTypeConfig:
		if login.Parent == nil || login.Parent.Type != userUserTypeConfig {
			return "" // must have a user parent
		}
		return login.Parent.path() + "/login/" + login.Name
	case domainUserTypeConfig:
		if login.Parent == nil || login.Parent.Type != userUserTypeConfig {
			return "" // must have a user parent
		}
		return login.Parent.path() + "/domain/" + login.Name
	}
	return "" // not a recognized login type
}

func (login *loginEntry) queryAccountData(txn *badger.Txn, path string, query string) error {
	acctPath := path + "/auth"
	gAcctData, err := GetBadgerVal(txn, acctPath)
	if err != nil {
		return err
	}
	if gAcctData == nil {
		return fmt.Errorf("Missing key path %s while fetching from %s", path, query)
	}
	acctData, ok := gAcctData.(map[string]interface{})
	if !ok {
		return fmt.Errorf("Unexpected account object %v while fetching from %s", gAcctData, acctPath)
	}

	var gPubKey interface{}
	gPubKey, ok = acctData["pubKey"]
	if ok {
		var pubKey string
		pubKey, ok = gPubKey.(string)
		if !ok {
			return fmt.Errorf("Found unexpected non-string %v reading %s/auth/pubKey", gPubKey, path)
		}
		login.Pubkey = pubKey
	} else {
		login.Pubkey = ""
	}

	var gParentSign interface{}
	gParentSign, ok = acctData["sign"]
	if ok {
		var parentSign string
		parentSign, ok = gParentSign.(string)
		if !ok {
			return fmt.Errorf("Found unexpected non-string %v reading %s/auth/sign", gParentSign, path)
		}
		login.ParentSign = parentSign
	} else {
		login.ParentSign = ""
	}

	return nil
}

func (login *loginEntry) assembleAccountData() map[string]interface{} {
	result := make(map[string]interface{})

	if login.Pubkey != "" {
		result["pubKey"] = login.Pubkey
	}
	if login.ParentSign != "" {
		result["sign"] = login.ParentSign
	}
	if login.Name != "" {
		result["name"] = login.Name
	}

	return nil
}

func (app *domainUserTypeStore) MatchFromPath(path string) (*userTypeConfig, string, string) {
	for _, typ := range app.userTypes {
		matches := typ.PathPat.FindStringSubmatch(path)
		if matches != nil {
			parentPath := ""
			loginName := ""
			if len(matches) > 1 {
				parentPath = matches[1]
				if len(matches) > 2 {
					loginName = matches[2]
				}
			}
			return typ, parentPath, loginName
		}
	}
	return nil, "", ""
}

func verifySignature(pubKey string, message string, sig string) bool {
	if len(pubKey) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify([]byte(pubKey), []byte(message), []byte(sig))
}

func (app *AthenaStoreApplication) isAuth(tx *athenaTx) (*loginEntry, error) {

	var login *loginEntry

	// Intentionally calling app.db.View rather than using any uncommitted transaction -- we want committed values here
	err := app.db.View(func(txn *badger.Txn) error {
		keyQuery := "keymap/" + base64.RawStdEncoding.EncodeToString(tx.Pkey)
		gKeyPath, err := GetBadgerVal(txn, keyQuery)
		if err != nil || gKeyPath == nil {
			return err // error or no key found
		}

		keyPath, ok := gKeyPath.(string)
		if !ok {
			return fmt.Errorf("Unexpected key path %v while fetching from %s", gKeyPath, keyQuery)
		}

		userType, parentPath, loginName := domainUserTypes.MatchFromPath(keyPath)
		if userType == nil {
			return fmt.Errorf("Unsupported key path %s while fetching from %s", keyPath, keyQuery)
		}

		login = &loginEntry{Type: userType, Name: loginName}
		err = login.queryAccountData(txn, keyPath, keyQuery)
		if err != nil {
			return err
		}

		if login.Pubkey == "" {
			return fmt.Errorf("Missing key path %s while fetching from %s", keyPath, keyQuery)
		}
		if login.Pubkey != string(tx.Pkey) {
			return fmt.Errorf("Pubkey mismatch: requested %s but resolved to %s",
				base64.RawStdEncoding.EncodeToString(tx.Pkey),
				base64.RawStdEncoding.EncodeToString([]byte(login.Pubkey)))
		}

		if parentPath != "" {
			if login.ParentSign == "" {
				return errors.New("Account is a child object but is missing a signature")
			}

			parentUserType, _, parentLoginName := domainUserTypes.MatchFromPath(parentPath)
			if parentUserType == nil {
				return fmt.Errorf("Unsupported parent key path %s", parentPath)
			}

			parentLogin := &loginEntry{Type: parentUserType, Name: parentLoginName}
			login.Parent = parentLogin
			err = parentLogin.queryAccountData(txn, parentPath, keyPath)
			if err != nil {
				return err
			}

			if parentLogin.Pubkey == "" {
				return fmt.Errorf("Account object %s/auth missing pubKey", parentPath)
			}
			if !verifySignature(parentLogin.Pubkey, string(tx.Pkey), login.ParentSign) {
				return errors.New("Account is a child object but its signature was failed by its parent")
			}

			return nil
		}
		return nil
	})
	return login, err
}

func (app *AthenaStoreApplication) createUser(txn *badger.Txn, login *loginEntry) error {
	if login == nil {
		return errors.New("Attempt to create an empty user")
	}
	path := login.path()
	if path == "" {
		return errors.New("Attempt to create an invalid user")
	}
	if login.Parent != nil {
		parentLogin := login.Parent
		parentPath := parentLogin.path()
		err := parentLogin.queryAccountData(txn, parentPath, parentPath)
		if err != nil {
			return err
		}
		if parentLogin.Pubkey == "" {
			return fmt.Errorf("Account object %s/auth missing pubKey", parentPath)
		}
		if !verifySignature(parentLogin.Pubkey, login.Pubkey, login.ParentSign) {
			return errors.New("Account is a child object but its signature was failed by its parent")
		}
	}

	acctPath := path + "/auth"
	gAcctData, err := GetBadgerVal(txn, acctPath)
	if gAcctData != nil || err != nil {
		return errors.New("Account already exists")
	}

	newAcctData, err := ToBadgerType(login.assembleAccountData())
	if err != nil {
		return err
	}
	err = txn.Set([]byte(acctPath), newAcctData)

	return err
}
