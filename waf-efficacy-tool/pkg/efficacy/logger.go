package efficacy

import (
	"fmt"
	"strings"
	"sync"
)

type Logger struct {
	level LogLevel
	mu    sync.Mutex
}

var globalLogger *Logger

func InitLogger(level LogLevel) {
	globalLogger = &Logger{
		level: level,
	}
}

func (l *Logger) log(level LogLevel, format string, args ...interface{}) {
	if l == nil {
		return
	}

	shouldLog := false
	switch l.level {
	case LogLevelSilent:
		shouldLog = false
	case LogLevelError:
		shouldLog = (level == LogLevelError)
	case LogLevelInfo:
		shouldLog = (level == LogLevelError || level == LogLevelInfo)
	case LogLevelDebug:
		shouldLog = true
	}

	if shouldLog {
		l.mu.Lock()
		defer l.mu.Unlock()
		
		prefix := ""
		switch level {
		case LogLevelError:
			prefix = "[ERROR] "
		case LogLevelInfo:
			prefix = "[INFO] "
		case LogLevelDebug:
			prefix = "[DEBUG] "
		}
		
		msg := fmt.Sprintf(format, args...)
		if !strings.HasSuffix(msg, "\n") {
			msg += "\n"
		}
		fmt.Print(prefix + msg)
	}
}

func Errorf(format string, args ...interface{}) {
	globalLogger.log(LogLevelError, format, args...)
}

func Infof(format string, args ...interface{}) {
	globalLogger.log(LogLevelInfo, format, args...)
}

func Debugf(format string, args ...interface{}) {
	globalLogger.log(LogLevelDebug, format, args...)
}

func PrintRaw(msg string) {
	if globalLogger != nil && globalLogger.level == LogLevelDebug {
		globalLogger.mu.Lock()
		defer globalLogger.mu.Unlock()
		fmt.Print(msg)
	}
}
