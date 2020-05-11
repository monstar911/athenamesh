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
	typeBytes       = 5
	typeArray       = 6
	typeMap         = 7
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
	case typeBytes:
		return val[1:], nil
	case typeArray:
		vals := make([]interface{}, 0)
		remain := val[1:]
		for len(remain) > 0 {
			entryLen, lenSize := readVarint(remain)
			if lenSize == 0 {
				return nil, errors.New("unexpected array element length")
			}
			entry, err := fromBadgerType(remain[lenSize : uint(entryLen)+lenSize])
			if err != nil {
				return nil, err
			}
			vals = append(vals, entry)
			remain = remain[uint(entryLen)+lenSize:]
		}
		return vals, nil
	case typeMap:
		vals := make(map[string]interface{})
		remain := val[1:]
		for len(remain) > 0 {
			keyLen, lenSize := readVarint(remain)
			if lenSize == 0 {
				return nil, errors.New("unexpected key element length")
			}
			key := string(remain[lenSize : uint(keyLen)+lenSize])
			remain = remain[uint(keyLen)+lenSize:]
			valueLen, lenSize := readVarint(remain)
			if lenSize == 0 {
				return nil, errors.New("unexpected value element length")
			}
			value, err := fromBadgerType(remain[lenSize : uint(valueLen)+lenSize])
			if err != nil {
				return nil, err
			}
			remain = remain[uint(valueLen)+lenSize:]
			vals[key] = value
		}
		return vals, nil
	default:
		return nil, fmt.Errorf("Unexpected datatype: %d", val[0])
	}
}

func toBadgerTypeUint(val uint64) []byte {
	bits := make([]byte, 8)
	binary.LittleEndian.PutUint64(bits, val)
	for len(bits) > 1 && bits[len(bits)-1] == 0 && bits[len(bits)-2] < 0x80 {
		bits = bits[:len(bits)-1]
	}
	return append(append([]byte{typeInt}, bits...), 0)
}

func toBadgerTypeInt(val int64) []byte {
	bits := make([]byte, 8)
	binary.LittleEndian.PutUint64(bits, uint64(val))
	for len(bits) > 1 && ((bits[len(bits)-1] == 0 && bits[len(bits)-2] < 0x80) || (bits[len(bits)-1] == 0xFF && bits[len(bits)-2] >= 0x80)) {
		bits = bits[:len(bits)-1]
	}
	return append([]byte{typeInt}, bits...)
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
	case float32:
		bits := make([]byte, 4)
		binary.LittleEndian.PutUint32(bits, math.Float32bits(v))
		ret := append([]byte{typeFloat}, bits...)
		return ret, nil
	case float64:
		bits := make([]byte, 8)
		binary.LittleEndian.PutUint64(bits, math.Float64bits(v))
		ret := append([]byte{typeFloat}, bits...)
		return ret, nil
	case uint8:
		return toBadgerTypeUint(uint64(v)), nil
	case uint16:
		return toBadgerTypeUint(uint64(v)), nil
	case uint32:
		return toBadgerTypeUint(uint64(v)), nil
	case uint64:
		return toBadgerTypeUint(v), nil
	case int8:
		return toBadgerTypeInt(int64(v)), nil
	case int16:
		return toBadgerTypeInt(int64(v)), nil
	case int32:
		return toBadgerTypeInt(int64(v)), nil
	case int64:
		return toBadgerTypeInt(v), nil
	case int:
		return toBadgerTypeInt(int64(v)), nil
	case uint:
		return toBadgerTypeUint(uint64(v)), nil
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
		if err == nil {
			return toBadgerTypeInt(num), nil
		}
		unum, err := strconv.ParseUint(string(v), 10, 64)
		if err != nil {
			return nil, err
		}
		// okay this is a *big* number that can only be stored as an unsigned long
		return toBadgerTypeUint(unum), nil

	case string:
		ret := append([]byte{typeString}, []byte(v)...)
		return ret, nil
	case []byte:
		ret := append([]byte{typeBytes}, v...)
		return ret, nil
	case []interface{}:
		result := []byte{typeArray}
		l := len(v)
		for i := 0; i < l; i++ {
			entry, err := ToBadgerType(v[i])
			if err != nil {
				return nil, err
			}
			result = append(append(result, writeVarint(uint64(len(entry)))...), entry...)
		}
		return result, nil
	case []string:
		result := []byte{typeArray}
		l := len(v)
		for i := 0; i < l; i++ {
			entry, err := ToBadgerType(v[i])
			if err != nil {
				return nil, err
			}
			result = append(append(result, writeVarint(uint64(len(entry)))...), entry...)
		}
		return result, nil
	case map[string]interface{}:
		result := []byte{typeMap}
		for key, value := range v {
			entry, err := ToBadgerType(value)
			if err != nil {
				return nil, err
			}
			result = append(append(append(append(result, writeVarint(uint64(len(key)))...), []byte(key)...),
				writeVarint(uint64(len(entry)))...), entry...)
		}
		return result, nil
	case nil:
		return nil, nil
	default:
		return nil, errors.New("Unsupported datatype")
	}
}

func readVarint(src []byte) (uint64, uint) {
	c := src[0]
	if c < 0x80 {
		return uint64(c), 1
	}
	if c < 0b11000000 {
		// unexpected continuation byte
		return 0, 0
	}
	var size uint
	var result uint64
	if c < 0b11100000 {
		size = 1
		result = uint64(c & 0b00011111)
	} else if c < 0b11110000 {
		size = 2
		result = uint64(c & 0b00001111)
	} else if c < 0b11111000 {
		size = 3
		result = uint64(c & 0b00000111)
	} else if c < 0b11111100 {
		size = 4
		result = uint64(c & 0b00000011)
	} else if c < 0b11111110 {
		size = 5
		result = uint64(c & 0b00000001)
	} else {
		size = 6
		result = 0
	}
	var idx uint
	for idx = 0; idx < size; idx++ {
		c = src[idx+1]
		if c&0b11000000 != 0b10000000 {
			// this isn't a continuation byte
			return 0, 0
		}
		result = result<<6 | uint64(src[idx+1]&0b00111111)
	}
	return result, size + 1
}

func writeVarint(val uint64) []byte {
	if val < 0x80 {
		return []byte{byte(val)}
	}
	var size uint
	var first byte
	if val < 0x00000800 { // 0000 0000 0000 0000 0000 0111 11|11 1111
		size = 1
		first = byte((val&0x000007C0)>>6 | 0b11000000)
	} else if val < 0x00010000 { // 0000 0000 0000 0000 1111 |1111 11|11 1111
		size = 2
		first = byte((val&0x0000F000)>>12 | 0b11100000)
	} else if val < 0x00200000 { // 0000 0000 0001 11|11 1111 |1111 11|11 1111
		size = 3
		first = byte((val&0x001C0000)>>18 | 0b11110000)
	} else if val < 0x04000000 { // 0000 0011 |1111 11|11 1111 |1111 11|11 1111
		size = 4
		first = byte((val&0x03000000)>>24 | 0b11111000)
	} else if val < 0x80000000 { // 01|11 1111 |1111 11|11 1111 |1111 11|11 1111
		size = 5
		first = byte((val&0x40000000)>>30 | 0b11111100)
	} else {
		size = 6
		first = 0b11111110
	}
	var idx uint
	result := make([]byte, size+1)
	for idx = 0; idx < size; idx++ {
		result[size-idx] = byte(val&0b111111) | 0b10000000
		val = val >> 6
	}
	result[0] = first
	return result
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
