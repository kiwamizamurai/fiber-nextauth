package nextauthjwt

import (
	"fmt"
	"log"
	"os"
)

type LogLevel int

const (
	LogLevelNone LogLevel = iota
	LogLevelError
	LogLevelWarn
	LogLevelInfo
	LogLevelDebug
)

type Logger interface {
	Debug(msg string, args ...interface{})
	Info(msg string, args ...interface{})
	Warn(msg string, args ...interface{})
	Error(msg string, args ...interface{})
}

type DefaultLogger struct {
	level  LogLevel
	logger *log.Logger
}

func NewDefaultLogger(level LogLevel) *DefaultLogger {
	return &DefaultLogger{
		level:  level,
		logger: log.New(os.Stderr, "", log.LstdFlags|log.Lmsgprefix),
	}
}

func (l *DefaultLogger) log(level LogLevel, msg string, args ...interface{}) {
	if l.level >= level {
		formattedMsg := fmt.Sprintf(msg, args...)
		switch level {
		case LogLevelError:
			l.logger.SetPrefix("ERROR: ")
			if err := l.logger.Output(2, formattedMsg); err != nil {
				fmt.Fprintf(os.Stderr, "failed to write log: %v\n", err)
			}
		case LogLevelWarn:
			l.logger.SetPrefix("WARN: ")
			if err := l.logger.Output(2, formattedMsg); err != nil {
				fmt.Fprintf(os.Stderr, "failed to write log: %v\n", err)
			}
		case LogLevelInfo:
			l.logger.SetPrefix("INFO: ")
			if err := l.logger.Output(2, formattedMsg); err != nil {
				fmt.Fprintf(os.Stderr, "failed to write log: %v\n", err)
			}
		case LogLevelDebug:
			l.logger.SetPrefix("DEBUG: ")
			if err := l.logger.Output(2, formattedMsg); err != nil {
				fmt.Fprintf(os.Stderr, "failed to write log: %v\n", err)
			}
		}
	}
}

func (l *DefaultLogger) Debug(msg string, args ...interface{}) {
	l.log(LogLevelDebug, msg, args...)
}

func (l *DefaultLogger) Info(msg string, args ...interface{}) {
	l.log(LogLevelInfo, msg, args...)
}

func (l *DefaultLogger) Warn(msg string, args ...interface{}) {
	l.log(LogLevelWarn, msg, args...)
}

func (l *DefaultLogger) Error(msg string, args ...interface{}) {
	l.log(LogLevelError, msg, args...)
}
