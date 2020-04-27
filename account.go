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
	Type       *userTypeConfig
	Name       string
	Parent     *loginEntry
	Pubkey     []byte
	ParentSign []byte
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
		var pubKey []byte
		pubKey, ok = gPubKey.([]byte)
		if !ok {
			return fmt.Errorf("Found unexpected non-string %v reading %s/auth/pubKey", gPubKey, path)
		}
		login.Pubkey = pubKey
	} else {
		login.Pubkey = []byte{}
	}

	var gParentSign interface{}
	gParentSign, ok = acctData["sign"]
	if ok {
		var parentSign []byte
		parentSign, ok = gParentSign.([]byte)
		if !ok {
			return fmt.Errorf("Found unexpected non-string %v reading %s/auth/sign", gParentSign, path)
		}
		login.ParentSign = parentSign
	} else {
		login.ParentSign = []byte{}
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
	if login.Name != "" {
		result["name"] = login.Name
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
