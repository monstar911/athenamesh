package app

// Manages the SymLink maps -- either the hardcoded pubkey symlinks or later chain-defined attribute-based symlinks
// All updates to the store pass through here in order to determine whether a symlink needs to be adjusted with the change

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/dgraph-io/badger"
)

type pubkeySymLinkMapEntry struct {
	PathPat    *regexp.Regexp // matches the source path, with a grouping for the destination of the symlink
	DestPrefix string         // where the symlink is created
}

type symLinkMapEntry struct {
	PathPat    *regexp.Regexp // matches the source path, with a grouping for the destination of the symlink
	SourceAttr string         // name of the attribute in the source path
	DestPrefix string         // where the symlink is created
}

var pubkeySymLinkPaths = []pubkeySymLinkMapEntry{
	{regexp.MustCompile("^(config/rootUser)/auth$"), "keyMap/"},
	{regexp.MustCompile("^(user/[^/]+)/auth$"), "keyMap/"},
	{regexp.MustCompile("^(user/[^/]+/login/[^/]+)/auth$"), "keyMap/"},
	{regexp.MustCompile("^(user/[^/]+/domain/[^/]+)/auth$"), "keyMap/"},
}

var symLinkPaths = []symLinkMapEntry{
	{regexp.MustCompile("^(user/[^/]+)/email$"), "hash", "users/email/"},
}

func (app *AthenaStoreApplication) setKey(txn *badger.Txn, path string, value interface{}) error {
	// are we matching any of our pubkey symlink paths?
	for _, typ := range pubkeySymLinkPaths {
		matches := typ.PathPat.FindStringSubmatch(path)
		if matches != nil {
			handlePubkeySymlinkChange(txn, path, matches[1], typ.DestPrefix, value)
		}
	}
	for _, typ := range symLinkPaths {
		matches := typ.PathPat.FindStringSubmatch(path)
		if matches != nil {
			handleSymlinkChange(txn, path, matches[1], typ.SourceAttr, typ.DestPrefix, value)
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

func resolveSymlinkPath(txn *badger.Txn, path string) (string, error) {
	segments := strings.Split(path, ":")
	for len(segments) > 1 {
		firstSeg := segments[0]

		// we have a symlink requested for this, we'll figure out what it is
		for _, typ := range pubkeySymLinkPaths {
			if len(typ.DestPrefix) > len(firstSeg) && typ.DestPrefix == typ.DestPrefix[:len(firstSeg)] {
				symDest, err := resolveSymlinkSeg(txn, firstSeg)
				if err != nil {
					return "", err
				}
				if symDest == "" {
					return "", nil // key doesn't resolve to anything
				}
				newSegment := fmt.Sprintf("%s/%s", symDest, segments[1])
				segments = append(strings.Split(newSegment, ":"), segments[2:]...)
				continue
			}
		}
		for _, typ := range symLinkPaths {
			if len(typ.DestPrefix) > len(firstSeg) && typ.DestPrefix == typ.DestPrefix[:len(firstSeg)] {
				symDest, err := resolveSymlinkSeg(txn, firstSeg)
				if err != nil {
					return "", err
				}
				if symDest == "" {
					return "", nil // key doesn't resolve to anything
				}
				newSegment := fmt.Sprintf("%s/%s", symDest, segments[1])
				segments = append(strings.Split(newSegment, ":"), segments[2:]...)
				continue
			}
		}
	}
	return segments[0], nil
}

func resolveSymlinkSeg(txn *badger.Txn, path string) (string, error) {
	linkPath, err := GetBadgerVal(txn, path)
	if err != nil {
		return "", err
	}
	if linkPath == nil {
		return "", nil
	}
	strLinkPath, ok := linkPath.(string)
	if !ok {
		return "", fmt.Errorf("symlink destination at %s has unexpected type", path)
	}
	return strLinkPath, nil
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
			if err == nil && gOldLinkPath != nil {
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

func handleSymlinkChange(txn *badger.Txn, srcPath string, linkPath string, sourceAttr string, destPrefix string, value interface{}) error {

	var newValue string
	var oldValue string

	// get the value we are changing from
	gOldData, err := GetBadgerVal(txn, srcPath)
	if err == nil && gOldData != nil {
		if oldData, ok := gOldData.(map[string]interface{}); ok {
			var gValue interface{}
			if gValue, ok = oldData[sourceAttr]; ok {
				var sValue string
				if sValue, ok = gValue.(string); ok {
					oldValue = sValue
				}
			}
		}
	}

	// get the value we are changing to
	if value != nil {
		if newData, ok := value.(map[string]interface{}); ok {
			var gValue interface{}
			if gValue, ok = newData[sourceAttr]; ok {
				var sValue string
				if sValue, ok = gValue.(string); ok {
					newValue = sValue
				}
			}
		}
	}

	if oldValue != newValue {
		if len(oldValue) > 0 {
			destPath := destPrefix + oldValue
			gOldLinkPath, err := GetBadgerVal(txn, destPath)
			if err == nil && gOldLinkPath != nil {
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
		if len(newValue) > 0 {
			destPath := destPrefix + newValue
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
