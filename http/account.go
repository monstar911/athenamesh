package http

import (
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	saltLength                      = 16
	targetTime        time.Duration = 2 * time.Second
	defaultMemory                   = 64 * 1024
	defaultIterations               = 15
)

var (
	parmParser = regexp.MustCompile("^\\$argon2([id]+).?\\$([^$]+)\\$(.+)$")
	keyParser  = regexp.MustCompile("^(\\S)=(\\d+)$")
)

type argonParams struct {
	isArgonID   bool
	memory      uint32
	iterations  uint32
	parallelism uint8
	salt        []byte
}

func (p argonParams) toString() string {
	if p.isArgonID {
		return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s",
			argon2.Version, p.memory, p.iterations, p.parallelism,
			base64.RawStdEncoding.EncodeToString(p.salt))
	}
	return fmt.Sprintf("$argon2i$v=%d$m=%d,t=%d,p=%d$%s",
		argon2.Version, p.memory, p.iterations, p.parallelism,
		base64.RawStdEncoding.EncodeToString(p.salt))
}

func (p *argonParams) fromString(val string) error {
	matches := parmParser.FindStringSubmatch(val)
	if matches == nil {
		return errors.New("does not match expected pattern")
	}

	switch matches[1] {
	case "id":
		p.isArgonID = true
	case "i":
		p.isArgonID = false
	case "d":
		return errors.New("Argon2d not supported")
	default:
		return errors.New("Unrecognized Argon2 algorithm")
	}

	var err error
	p.salt, err = base64.RawStdEncoding.DecodeString(matches[3])
	if err != nil {
		return err
	}

	for _, entry := range strings.Split(matches[2], ",") {
		keyMatches := keyParser.FindStringSubmatch(entry)
		if keyMatches == nil {
			return fmt.Errorf("parameter %s is not in the expected format", entry)
		}
		val, _ := strconv.ParseInt(keyMatches[2], 10, 32) // no need to check err, we've already validated this in the regex
		switch keyMatches[1] {
		case "m":
			p.memory = uint32(val)
		case "t":
			p.iterations = uint32(val)
		case "p":
			p.parallelism = uint8(val)
		}
	}
	return nil
}

// KeyFromPassword given an existing parameter string and a password, create a private key
func KeyFromPassword(parms string, password string) (ed25519.PrivateKey, error) {
	decParms := &argonParams{}
	err := decParms.fromString(parms)
	if err != nil {
		return nil, err
	}

	if decParms.salt == nil {
		return nil, errors.New("argon2: missing salt")
	}
	if decParms.memory < 1024 {
		return nil, errors.New("argon2: memory usage too low")
	}
	if decParms.iterations < 1 {
		return nil, errors.New("argon2: number of rounds too small")
	}
	if decParms.parallelism < 1 {
		return nil, errors.New("argon2: parallelism degree too low")
	}
	var seed []byte
	if decParms.isArgonID {
		seed = argon2.IDKey([]byte(password), decParms.salt, decParms.iterations, decParms.memory, decParms.parallelism, ed25519.SeedSize)
	} else {
		seed = argon2.Key([]byte(password), decParms.salt, decParms.iterations, decParms.memory, decParms.parallelism, ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// GenerateFromPassword generates a new password, attempting to create appropriate parameters
func GenerateFromPassword(password string) (string, ed25519.PrivateKey, error) {
	// Establish the parameters to use for Argon2.
	p := &argonParams{
		isArgonID:   true,
		memory:      defaultMemory,
		iterations:  defaultIterations,
		parallelism: uint8(runtime.NumCPU()),
	}

	// Generate a cryptographically secure random salt.
	p.salt = make([]byte, saltLength)
	_, err := cryptorand.Reader.Read(p.salt)
	if err != nil {
		return "", nil, err
	}

	// Pass the plaintext password and parameters to our generateFromPassword
	// helper function.
	var seed []byte
	for {
		start := time.Now()
		seed = argon2.IDKey([]byte(password), p.salt, p.iterations, p.memory, p.parallelism, ed25519.SeedSize)
		durn := time.Now().Sub(start)

		if durn > (targetTime*3/2) && (p.iterations > defaultIterations || p.memory > defaultMemory) {
			// time too high, bring it down
			factor := 0.9 * float64(durn) / float64(targetTime)
			p.iterations = uint32(float64(p.iterations)/factor + 0.5)
			if p.iterations < defaultIterations {
				if p.memory > defaultMemory {
					p.memory = p.memory / 2
					p.iterations = p.iterations * 2
					if p.memory < defaultMemory {
						p.memory = defaultMemory
					}
				} else {
					p.iterations = defaultIterations
				}
			}
		} else if durn > targetTime*3/4 {
			// time is acceptible, return what we have
			break
		} else {
			// time too low, bring it up
			factor := 0.9 * float64(targetTime) / float64(durn)
			p.iterations = uint32(float64(p.iterations)*factor + 0.5)
			if p.iterations > defaultIterations*2 {
				p.memory = p.memory * 2
				p.iterations = defaultIterations
			}
		}
	}

	return p.toString(), ed25519.NewKeyFromSeed(seed), nil
}
