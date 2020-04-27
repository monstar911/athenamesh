package main

import (
	"fmt"
	"strings"

	badgerlog "github.com/dgraph-io/badger"
	tmlog "github.com/tendermint/tendermint/libs/log"
)

type badgerLogger struct {
	logger tmlog.Logger
}

func (log *badgerLogger) Errorf(msg string, vals ...interface{}) {
	fullMsg := fmt.Sprintf(strings.TrimRight(msg, " \r\n"), vals...)
	log.logger.Error("badger: " + fullMsg)
}

func (log *badgerLogger) Warningf(msg string, vals ...interface{}) {
	fullMsg := fmt.Sprintf(strings.TrimRight(msg, " \r\n"), vals...)
	log.logger.Error("badger: " + fullMsg)
}

func (log *badgerLogger) Infof(msg string, vals ...interface{}) {
	fullMsg := fmt.Sprintf(strings.TrimRight(msg, " \r\n"), vals...)
	log.logger.Info("badger: " + fullMsg)
}

func (log *badgerLogger) Debugf(msg string, vals ...interface{}) {
	fullMsg := fmt.Sprintf(strings.TrimRight(msg, " \r\n"), vals...)
	log.logger.Debug("badger: " + fullMsg)
}

func newBadgerLogger(logger tmlog.Logger) badgerlog.Logger {
	return &badgerLogger{logger: logger}
}
