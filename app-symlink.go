package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"regexp"

	"github.com/dgraph-io/badger"
)

type pubkeySymLinkMapEntry struct {
	PathPat    *regexp.Regexp
	DestPrefix string
}

var pubkeySymLinkPaths = []pubkeySymLinkMapEntry{
	{regexp.MustCompile("^(config/rootUser)/auth$"), "keyMap/"},
	{regexp.MustCompile("^(user/[^/]+)/auth$"), "keyMap/"},
	{regexp.MustCompile("^(user/[^/]+/login/[^/]+)/auth$"), "keyMap/"},
	{regexp.MustCompile("^(user/[^/]+/domain/[^/]+)/auth$"), "keyMap/"},
}

func (app *AthenaStoreApplication) setKey(txn *badger.Txn, path string, value interface{}) error {
	// are we matching any of our pubkey symlink paths?
	for _, typ := range pubkeySymLinkPaths {
		matches := typ.PathPat.FindStringSubmatch(path)
		if matches != nil {
			handlePubkeySymlinkChange(txn, path, matches[1], typ.DestPrefix, value)
		}
	}

	// delete the value if requested
	if value == nil {
		return txn.Delete([]byte(path))
	}

	// otherwise convert the value to a binary and write it out
	encData, err := ToBadgerType(value)
	if err != nil {
		return err
	}
	return txn.Set([]byte(path), encData)
}

func handlePubkeySymlinkChange(txn *badger.Txn, srcPath string, linkPath string, destPrefix string, value interface{}) error {

	var newPubKey []byte
	var oldPubKey []byte

	// get the value we are changing from
	gOldAcctData, err := GetBadgerVal(txn, srcPath)
	if err == nil && gOldAcctData != nil {
		if oldAcctData, ok := gOldAcctData.(map[string]interface{}); ok {
			var gPubKey interface{}
			if gPubKey, ok = oldAcctData["pubKey"]; ok {
				var pubKey []byte
				if pubKey, ok = gPubKey.([]byte); ok {
					oldPubKey = pubKey
				}
			}
		}
	}

	// get the value we are changing to
	if value != nil {
		if newAcctData, ok := value.(map[string]interface{}); ok {
			var gPubKey interface{}
			if gPubKey, ok = newAcctData["pubKey"]; ok {
				var pubKey []byte
				if pubKey, ok = gPubKey.([]byte); ok {
					newPubKey = pubKey
				}
			}
		}
	}

	if !bytes.Equal(oldPubKey, newPubKey) {
		if len(oldPubKey) > 0 {
			destPath := destPrefix + base64.RawURLEncoding.EncodeToString(oldPubKey)
			gOldLinkPath, err := GetBadgerVal(txn, destPath)
			if err == nil {
				if oldLinkPath, ok := gOldLinkPath.(string); ok {
					if oldLinkPath == linkPath {
						err = txn.Delete([]byte(destPath))
						if err != nil {
							return err
						}
					}
				}
			}
		}
		if len(newPubKey) > 0 {
			destPath := destPrefix + base64.RawURLEncoding.EncodeToString(newPubKey)
			gOldLinkPath, err := GetBadgerVal(txn, destPath)
			if err == nil && gOldLinkPath != nil {
				return errors.New("Unexpected: there is already a symlink declared at " + destPath)
			}
			encLinkPath, err := ToBadgerType(linkPath)
			if err != nil {
				return err
			}
			return txn.Set([]byte(destPath), encLinkPath)
		}
	}

	return nil
}
