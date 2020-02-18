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
	typeFloat       = 3
	typeString      = 4
)

// NumberToUint64 attempts to convert numeric val to a uint64
func NumberToUint64(val interface{}) (uint64, bool) {
	switch v := val.(type) {
	case uint64:
		return v, true
	case int64:
		if v < 0 {
			return uint64(v), false
		}
		return uint64(v), true
	case int32:
		if v < 0 {
			return uint64(v), false
		}
		return uint64(v), true
	case uint32:
		return uint64(v), true
	case int:
		if v < 0 {
			return uint64(v), false
		}
		return uint64(v), true
	case uint:
		return uint64(v), true
	}
	return 0, false
}

// NumberToInt64 attempts to convert numeric val to an int64
func NumberToInt64(val interface{}) (int64, bool) {
	switch v := val.(type) {
	case uint64:
		return int64(v), true
	case int64:
		return int64(v), true
	case int32:
		return int64(v), true
	case uint32:
		return int64(v), true
	case int:
		return int64(v), true
	case uint:
		return int64(v), true
	}
	return 0, false
}

// NumberToUint attempts to convert numeric val to a uint
func NumberToUint(val interface{}) (uint, bool) {
	switch v := val.(type) {
	case uint64:
		return uint(v), true
	case int64:
		if v < 0 {
			return uint(v), false
		}
		return uint(v), true
	case int32:
		if v < 0 {
			return uint(v), false
		}
		return uint(v), true
	case uint32:
		return uint(v), true
	case int:
		if v < 0 {
			return uint(v), false
		}
		return uint(v), true
	case uint:
		return v, true
	}
	return 0, false
}

// NumberToInt attempts to convert numeric val to an int
func NumberToInt(val interface{}) (int, bool) {
	switch v := val.(type) {
	case uint64:
		return int(v), true
	case int64:
		return int(v), true
	case int32:
		return int(v), true
	case uint32:
		return int(v), true
	case int:
		return int(v), true
	case uint:
		return int(v), true
	}
	return 0, false
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
		switch len(val) {
		case 10:
			// just assume this is a ulong that might exceed long limits, can't really do anything else
			return binary.LittleEndian.Uint64(val[1:9]), nil
		case 9, 8, 7, 6:
			bits := val[1:]
			if bits[len(bits)-1] >= 0x80 {
				bits = append(bits, 0xff, 0xff, 0xff)[:8]
			} else {
				bits = append(bits, 0, 0, 0)[:8]
			}
			return int64(binary.LittleEndian.Uint64(bits)), nil
		case 5, 4, 3, 2:
			bits := val[1:]
			if bits[len(bits)-1] >= 0x80 {
				bits = append(bits, 0xff, 0xff, 0xff)[:8]
			} else {
				bits = append(bits, 0, 0, 0)[:8]
			}
			return int32(binary.LittleEndian.Uint32(bits)), nil
		default:
			return nil, errors.New("unexpected data length")
		}
	case typeFloat:
		switch len(val) {
		case 5:
			return math.Float32frombits(binary.LittleEndian.Uint32(val[1:9])), nil
		case 9:
			return math.Float64frombits(binary.LittleEndian.Uint64(val[1:9])), nil
		default:
			return nil, errors.New("unexpected data length")
		}
	case typeString:
		return string(val[1:]), nil
	default:
		return nil, fmt.Errorf("Unexpected datatype: %d", val[0])
	}
}

// ToBadgerType convert the specified scalar into something stored in a Badger KV store
func ToBadgerType(val interface{}) ([]byte, error) {
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
			ret := append([]byte{typeFloat}, bits...)
			return ret, nil
		}
		num, err := strconv.ParseInt(string(v), 10, 64)
		if err != nil {
			unum, err := strconv.ParseUint(string(v), 10, 64)
			if err != nil {
				return nil, err
			}
			// okay this is a *big* number that can only be stored as an unsigned long
			bits := make([]byte, 8)
			binary.LittleEndian.PutUint64(bits, unum)
			ret := append(append([]byte{typeInt}, bits...), 0)
			return ret, nil
		}

		bits := make([]byte, 8)
		binary.LittleEndian.PutUint64(bits, uint64(num))
		for len(bits) > 1 && (bits[len(bits)-1] == 0 && bits[len(bits)-2] < 0x80) || (bits[len(bits)-1] == 0xFF && bits[len(bits)-2] >= 0x80) {
			bits = bits[:len(bits)-1]
		}
		ret := append([]byte{typeInt}, bits...)
		return ret, nil
	case string:
		ret := append([]byte{typeString}, []byte(v)...)
		return ret, nil
	case nil:
		return nil, nil
	default:
		return nil, errors.New("Unsupported datatype")
	}
}

// GetBadgerVal retrieve the specified key as a scalar from a Badger KV store
func GetBadgerVal(txn *badger.Txn, key string) (interface{}, error) {
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
		result = iVal
		return nil
	})
	return result, err
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

// GetBadgerTree retrieve the specified key as a scalar or subtree from a Badger KV store
func GetBadgerTree(txn *badger.Txn, key string) (interface{}, error) {
	item, err := txn.Get([]byte(key))
	if err != nil {
		if err != badger.ErrKeyNotFound {
			// some error happened, just fail out now
			return nil, err
		}
		val := map[string]interface{}{}
		foundOne := false
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
		if foundOne {
			return val, nil // we found an object with nested values, return it
		}
		return nil, nil // didn't find anything, just return empty
	}

	// we found a single value, return it
	var result interface{}
	err = item.Value(func(val []byte) error {
		iVal, err := fromBadgerType(val)
		if err != nil {
			return err
		}
		result = iVal
		return nil
	})
	return result, err
}
