package main

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/dgraph-io/badger"
)

type userTypeConfig struct {
	UsePassphrase bool
	PathPat       *regexp.Regexp
	ParentIdx     int
	NameIdx       int
}

var rootUserTypeConfig = &userTypeConfig{
	UsePassphrase: false,
	PathPat:       regexp.MustCompile("^config/rootUser$"),
}

var userUserTypeConfig = &userTypeConfig{
	UsePassphrase: true,
	PathPat:       regexp.MustCompile("^user/([^/]+)$"),
	NameIdx:       1,
}

var loginUserTypeConfig = &userTypeConfig{
	UsePassphrase: false,
	PathPat:       regexp.MustCompile("^(user/[^/]+)/login/([^/]+)$"),
	ParentIdx:     1,
	NameIdx:       2,
}

var domainUserTypeConfig = &userTypeConfig{
	UsePassphrase: false,
	PathPat:       regexp.MustCompile("^(user/[^/]+)/domain/([^/]+)$"),
	ParentIdx:     1,
	NameIdx:       2,
}

type domainUserTypeStore struct {
	userTypes []*userTypeConfig
}

var domainUserTypes = &domainUserTypeStore{
	userTypes: []*userTypeConfig{rootUserTypeConfig, userUserTypeConfig, loginUserTypeConfig, domainUserTypeConfig},
}

type loginEntry struct {
	Type       *userTypeConfig        // from path -- type of this login
	Name       string                 // from path -- name of this login (may be different from stored in /auth)
	Parent     *loginEntry            // from path -- parent to this login
	Pubkey     []byte                 // from /auth key
	ParentSign []byte                 // from /auth key
	Attrs      map[string]interface{} // other /auth keys
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

	login.Pubkey = []byte{}
	login.ParentSign = []byte{}
	login.Attrs = make(map[string]interface{})
	for key, val := range acctData {
		switch key {
		case "pubKey":
			var pubKey []byte
			pubKey, ok = val.([]byte)
			if !ok {
				return fmt.Errorf("Found unexpected non-string %v reading %s/auth/pubKey", val, path)
			}
			login.Pubkey = pubKey
		case "sign":
			var parentSign []byte
			parentSign, ok = val.([]byte)
			if !ok {
				return fmt.Errorf("Found unexpected non-string %v reading %s/auth/sign", val, path)
			}
			login.ParentSign = parentSign
		default:
			login.Attrs[key] = val
		}
	}

	return nil
}

func (login *loginEntry) assembleAccountData() map[string]interface{} {
	result := make(map[string]interface{})

	if len(login.Pubkey) > 0 {
		result["pubKey"] = login.Pubkey
	}
	if len(login.ParentSign) > 0 {
		result["sign"] = login.ParentSign
	}
	if login.Attrs != nil {
		for key, val := range login.Attrs {
			result[key] = val
		}
	}

	return nil
}

func (app *domainUserTypeStore) MatchFromPath(path string) (*loginEntry, string) {
	for _, typ := range app.userTypes {
		matches := typ.PathPat.FindStringSubmatch(path)
		if matches != nil {
			login := &loginEntry{Type: typ}
			parentPath := ""
			if typ.ParentIdx > 0 && len(matches) > typ.ParentIdx {
				parentPath = matches[typ.ParentIdx]
			}
			if typ.NameIdx > 0 && len(matches) > typ.NameIdx {
				login.Name = matches[typ.NameIdx]
			}
			return login, parentPath
		}
	}
	return nil, ""
}
