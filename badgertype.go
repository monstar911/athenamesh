package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/dgraph-io/badger"
)

const (
	typeBool   byte = 1
	typeInt         = 2
	typeLong        = 3
	typeDouble      = 4
	typeString      = 5
	typeLink        = 6
)

// Link represents a reference to a different key
type Link string

const maxLinkDepth = 5

const maxUint32 = ^uint32(0)
const minUint32 = 0
const maxInt32 = int(maxUint32 >> 1)
const minInt32 = -maxInt32 - 1

func abs(n int64) int64 { // http://cavaliercoder.com/blog/optimized-abs-for-int64-in-go.html
	y := n >> 63       // y ← x ⟫ 63
	return (n ^ y) - y // (x ⨁ y) - y
}

func fromBadgerType(val []byte) (interface{}, error) {
	if val == nil || len(val) == 0 {
		return nil, errors.New("cannot interpret empty string")
	}
	switch val[0] {
	case typeBool:
		if len(val) < 2 {
			return nil, errors.New("data too short")
		}
		return val[1] != 0, nil
	case typeInt:
		if len(val) < 5 {
			return nil, errors.New("data too short")
		}
		return int(binary.LittleEndian.Uint32(val[1:5])), nil
	case typeLong:
		if len(val) < 9 {
			return nil, errors.New("data too short")
		}
		return int64(binary.LittleEndian.Uint64(val[1:9])), nil
	case typeDouble:
		if len(val) < 9 {
			return nil, errors.New("data too short")
		}
		return math.Float64frombits(binary.LittleEndian.Uint64(val[1:9])), nil
	case typeString:
		return string(val[1:]), nil
	case typeLink:
		return Link(val[1:]), nil
	default:
		return nil, fmt.Errorf("Unexpected datatype: %d", val[0])
	}
}

func toBadgerType(val interface{}) ([]byte, error) {
	switch v := val.(type) {
	case bool:
		ret := make([]byte, 2)
		ret[0] = typeBool
		if v {
			ret[1] = 1
		} else {
			ret[1] = 0
		}
		return ret, nil
	case json.Number:
		if strings.Contains(string(v), ".") {
			num, err := strconv.ParseFloat(string(v), 64)
			if err != nil {
				return nil, err
			}
			bits := make([]byte, 8)
			binary.LittleEndian.PutUint64(bits, math.Float64bits(num))
			ret := append([]byte{typeDouble}, bits...)
			return ret, nil
		}
		num, err := strconv.ParseInt(string(v), 10, 64)
		if err != nil {
			return nil, err
		}
		if abs(num) < int64(maxInt32) {
			bits := make([]byte, 4)
			binary.LittleEndian.PutUint32(bits, uint32(num))
			ret := append([]byte{typeInt}, bits...)
			return ret, nil
		}
		bits := make([]byte, 8)
		binary.LittleEndian.PutUint64(bits, uint64(num))
		ret := append([]byte{typeLong}, bits...)
		return ret, nil
	case string:
		ret := append([]byte{typeString}, []byte(v)...)
		return ret, nil
	case Link:
		ret := append([]byte{typeLink}, []byte(v)...)
		return ret, nil
	case nil:
		return nil, nil
	default:
		return nil, errors.New("Unsupported datatype")
	}
}

func getBadgerValImpl(txn *badger.Txn, key string, maxDepth int) (interface{}, error) {
	item, err := txn.Get([]byte(key))
	if err != nil {
		if err == badger.ErrKeyNotFound {
			return nil, nil
		}
		return nil, err
	}
	var result interface{}
	err = item.Value(func(val []byte) error {
		iVal, err := fromBadgerType(val)
		if err != nil {
			return err
		}
		if link, ok := iVal.(Link); ok {
			if maxDepth == 0 {
				return errors.New("Links nested too deeply")
			}
			result, err = getBadgerValImpl(txn, string(link), maxDepth-1)
			return err
		}
		result = iVal
		return nil
	})
	return result, err
}

func getBadgerVal(txn *badger.Txn, key string) (interface{}, error) {
	return getBadgerValImpl(txn, key, maxLinkDepth)
}

func storeDenseKey(store map[string]interface{}, key string, val interface{}) {
	slashPos := strings.Index(key, "/")
	if slashPos < 0 {
		store[key] = val
		return
	}

	head := key[0:slashPos]
	body := key[slashPos+1:]
	if sub, ok := store[head]; ok {
		if subMap, ok := sub.(map[string]interface{}); ok {
			storeDenseKey(subMap, body, val)
		}
		return
	}
	subMap := map[string]interface{}{}
	store[head] = subMap
	storeDenseKey(subMap, body, val)
}

func getBadgerTreeImpl(txn *badger.Txn, key string, maxDepth int) (interface{}, error) {
	item, err := txn.Get([]byte(key))
	if err != nil {
		if err != badger.ErrKeyNotFound {
			return nil, err
		}
		val := map[string]interface{}{}
		iter := txn.NewIterator(badger.DefaultIteratorOptions)
		defer iter.Close()
		prefix := append([]byte(key), byte('/'))
		for iter.Seek(prefix); iter.ValidForPrefix(prefix); iter.Next() {
			item := iter.Item()
			err := item.Value(func(v []byte) error {
				iVal, err := fromBadgerType(v)
				if err != nil {
					return err
				}
				storeDenseKey(val, string(item.Key()[len(prefix):]), iVal)
				return nil
			})
			if err != nil {
				return nil, err
			}
		}
		return val, nil
	}
	var result interface{}
	err = item.Value(func(val []byte) error {
		iVal, err := fromBadgerType(val)
		if err != nil {
			return err
		}
		if link, ok := iVal.(Link); ok {
			if maxDepth == 0 {
				return errors.New("Links nested too deeply")
			}
			result, err = getBadgerValImpl(txn, string(link), maxDepth-1)
			return err
		}
		result = iVal
		return nil
	})
	return result, err
}
