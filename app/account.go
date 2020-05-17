package app

// Defines the various types of accounts we support, where they appear in the KV store, and assists
// in encoding/decoding the values for communicating either with the store or with the client

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"

	"github.com/dgraph-io/badger"
)

type userTypeConfig struct {
	UsePassphrase bool           // true if this account uses a passphrase to identify itself (unused?)
	PathPat       *regexp.Regexp // Identifies a user account from its path
	ParentIdx     int            // regex grouping in PathPat that represents the path of its parent
	NameIdx       int            // regex grouping in PathPat that represents the "name" of this account
	TypeName      string         // keyword describing this type -- used as part of parent hashes
}

var rootUserTypeConfig = &userTypeConfig{
	UsePassphrase: false,
	PathPat:       regexp.MustCompile("^config/rootUser$"),
	TypeName:      "root",
}

var userUserTypeConfig = &userTypeConfig{
	UsePassphrase: true,
	PathPat:       regexp.MustCompile("^user/([^/]+)$"),
	NameIdx:       1,
	TypeName:      "user",
}

var loginUserTypeConfig = &userTypeConfig{
	UsePassphrase: false,
	PathPat:       regexp.MustCompile("^(user/[^/]+)/login/([^/]+)$"),
	ParentIdx:     1,
	NameIdx:       2,
	TypeName:      "login",
}

var domainUserTypeConfig = &userTypeConfig{
	UsePassphrase: false,
	PathPat:       regexp.MustCompile("^(user/[^/]+)/domain/([^/]+)$"),
	ParentIdx:     1,
	NameIdx:       2,
	TypeName:      "domain",
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
	Created    int64
	Expires    int64
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

	return login.decodeAccountData(acctData, path, false)
}

func (login *loginEntry) decodeAccountData(acctData map[string]interface{}, path string, fromUser bool) error {
	login.Pubkey = []byte{}
	login.ParentSign = []byte{}
	login.Attrs = make(map[string]interface{})
	for key, val := range acctData {
		switch key {
		case "pubKey":
			if pubKey, ok := val.([]byte); ok {
				login.Pubkey = pubKey
			} else if pubKey, ok := val.(string); ok {
				decPubKey, err := base64.RawURLEncoding.DecodeString(pubKey)
				if err != nil {
					return err
				}
				login.Pubkey = decPubKey
			} else {
				return fmt.Errorf("Found unexpected non-string %v reading %s/auth/pubKey", val, path)
			}
		case "sign":
			if parentSign, ok := val.([]byte); ok {
				login.ParentSign = parentSign
			} else if parentSign, ok := val.(string); ok {
				decParentSign, err := base64.RawURLEncoding.DecodeString(parentSign)
				if err != nil {
					return err
				}
				login.ParentSign = decParentSign
			} else {
				return fmt.Errorf("Found unexpected non-string %v reading %s/auth/sign", val, path)
			}
		case "created":
			if !fromUser {
				if iCreated, ok := NumberToInt64(val); ok {
					login.Created = iCreated
				} else {
					return fmt.Errorf("Found unexpected non-string %v reading %s/auth/created", val, path)
				}
			}
		case "expires":
			if iExpires, ok := NumberToInt64(val); ok {
				login.Expires = iExpires
			} else {
				return fmt.Errorf("Found unexpected non-string %v reading %s/auth/created", val, path)
			}
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
	if login.Created > 0 {
		result["created"] = login.Created
	}
	if login.Expires > 0 {
		result["expires"] = login.Expires
	}
	if login.Attrs != nil {
		for key, val := range login.Attrs {
			result[key] = val
		}
	}

	return nil
}

func (login *loginEntry) assembleQueryData() map[string]interface{} {
	result := make(map[string]interface{})

	if len(login.Pubkey) > 0 {
		result["pubKey"] = base64.RawURLEncoding.EncodeToString(login.Pubkey)
	}
	if len(login.ParentSign) > 0 {
		result["sign"] = base64.RawURLEncoding.EncodeToString(login.ParentSign)
	}
	if login.Created > 0 {
		result["created"] = login.Created
	}
	if login.Expires > 0 {
		result["expires"] = login.Expires
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
