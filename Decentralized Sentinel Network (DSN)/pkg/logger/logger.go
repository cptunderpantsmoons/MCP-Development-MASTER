package logger

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Logger interface defines the logging methods
type Logger interface {
	Debug(msg string, fields ...interface{})
	Info(msg string, fields ...interface{})
	Warn(msg string, fields ...interface{})
	Error(msg string, fields ...interface{})
	Fatal(msg string, fields ...interface{})
	
	With(fields ...interface{}) Logger
	WithError(err error) Logger
	WithField(key string, value interface{}) Logger
	WithFields(fields map[string]interface{}) Logger
}

// Config holds logger configuration
type Config struct {
	Level  string
	Format string
	Output string
	Debug  bool
}

// zapLogger implements Logger interface using zap
type zapLogger struct {
	logger *zap.SugaredLogger
}

// logrusLogger implements Logger interface using logrus
type logrusLogger struct {
	logger *logrus.Logger
	entry  *logrus.Entry
}

// New creates a new logger instance based on configuration
func New(config Config) (Logger, error) {
	switch strings.ToLower(config.Format) {
	case "json":
		return newZapLogger(config)
	case "text":
		return newLogrusLogger(config)
	default:
		return newZapLogger(config) // Default to zap with JSON
	}
}

// newZapLogger creates a new zap-based logger
func newZapLogger(config Config) (Logger, error) {
	level, err := parseZapLevel(config.Level)
	if err != nil {
		return nil, fmt.Errorf("invalid log level: %w", err)
	}

	// Configure encoder
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.TimeKey = "timestamp"
	encoderConfig.LevelKey = "level"
	encoderConfig.MessageKey = "message"
	encoderConfig.CallerKey = "caller"
	encoderConfig.StacktraceKey = "stacktrace"
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderConfig.EncodeLevel = zapcore.LowercaseLevelEncoder
	encoderConfig.EncodeCaller = zapcore.ShortCallerEncoder

	// Configure output
	var output zapcore.WriteSyncer
	switch config.Output {
	case "stdout":
		output = zapcore.AddSync(os.Stdout)
	case "stderr":
		output = zapcore.AddSync(os.Stderr)
	case "":
		output = zapcore.AddSync(os.Stdout) // Default
	default:
		// File output
		file, err := os.OpenFile(config.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %w", err)
		}
		output = zapcore.AddSync(file)
	}

	// Create core
	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(encoderConfig),
		output,
		level,
	)

	// Add caller and stacktrace for development
	var options []zap.Option
	if config.Debug {
		options = append(options, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))
	}

	logger := zap.New(core, options...)
	
	return &zapLogger{
		logger: logger.Sugar(),
	}, nil
}

// newLogrusLogger creates a new logrus-based logger
func newLogrusLogger(config Config) (Logger, error) {
	logger := logrus.New()

	// Set level
	level, err := parseLogrusLevel(config.Level)
	if err != nil {
		return nil, fmt.Errorf("invalid log level: %w", err)
	}
	logger.SetLevel(level)

	// Set formatter
	if config.Format == "json" {
		logger.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: "2006-01-02T15:04:05.000Z07:00",
			FieldMap: logrus.FieldMap{
				logrus.FieldKeyTime:  "timestamp",
				logrus.FieldKeyLevel: "level",
				logrus.FieldKeyMsg:   "message",
				logrus.FieldKeyFunc:  "caller",
			},
		})
	} else {
		logger.SetFormatter(&logrus.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: "2006-01-02T15:04:05.000Z07:00",
		})
	}

	// Set output
	var output io.Writer
	switch config.Output {
	case "stdout":
		output = os.Stdout
	case "stderr":
		output = os.Stderr
	case "":
		output = os.Stdout // Default
	default:
		// File output
		file, err := os.OpenFile(config.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %w", err)
		}
		output = file
	}
	logger.SetOutput(output)

	// Enable caller reporting for debug mode
	if config.Debug {
		logger.SetReportCaller(true)
	}

	return &logrusLogger{
		logger: logger,
		entry:  logrus.NewEntry(logger),
	}, nil
}

// Zap logger implementation
func (l *zapLogger) Debug(msg string, fields ...interface{}) {
	l.logger.Debugw(msg, fields...)
}

func (l *zapLogger) Info(msg string, fields ...interface{}) {
	l.logger.Infow(msg, fields...)
}

func (l *zapLogger) Warn(msg string, fields ...interface{}) {
	l.logger.Warnw(msg, fields...)
}

func (l *zapLogger) Error(msg string, fields ...interface{}) {
	l.logger.Errorw(msg, fields...)
}

func (l *zapLogger) Fatal(msg string, fields ...interface{}) {
	l.logger.Fatalw(msg, fields...)
}

func (l *zapLogger) With(fields ...interface{}) Logger {
	return &zapLogger{
		logger: l.logger.With(fields...),
	}
}

func (l *zapLogger) WithError(err error) Logger {
	return &zapLogger{
		logger: l.logger.With("error", err),
	}
}

func (l *zapLogger) WithField(key string, value interface{}) Logger {
	return &zapLogger{
		logger: l.logger.With(key, value),
	}
}

func (l *zapLogger) WithFields(fields map[string]interface{}) Logger {
	var keyValues []interface{}
	for k, v := range fields {
		keyValues = append(keyValues, k, v)
	}
	return &zapLogger{
		logger: l.logger.With(keyValues...),
	}
}

// Logrus logger implementation
func (l *logrusLogger) Debug(msg string, fields ...interface{}) {
	l.entry.WithFields(parseFields(fields...)).Debug(msg)
}

func (l *logrusLogger) Info(msg string, fields ...interface{}) {
	l.entry.WithFields(parseFields(fields...)).Info(msg)
}

func (l *logrusLogger) Warn(msg string, fields ...interface{}) {
	l.entry.WithFields(parseFields(fields...)).Warn(msg)
}

func (l *logrusLogger) Error(msg string, fields ...interface{}) {
	l.entry.WithFields(parseFields(fields...)).Error(msg)
}

func (l *logrusLogger) Fatal(msg string, fields ...interface{}) {
	l.entry.WithFields(parseFields(fields...)).Fatal(msg)
}

func (l *logrusLogger) With(fields ...interface{}) Logger {
	return &logrusLogger{
		logger: l.logger,
		entry:  l.entry.WithFields(parseFields(fields...)),
	}
}

func (l *logrusLogger) WithError(err error) Logger {
	return &logrusLogger{
		logger: l.logger,
		entry:  l.entry.WithError(err),
	}
}

func (l *logrusLogger) WithField(key string, value interface{}) Logger {
	return &logrusLogger{
		logger: l.logger,
		entry:  l.entry.WithField(key, value),
	}
}

func (l *logrusLogger) WithFields(fields map[string]interface{}) Logger {
	return &logrusLogger{
		logger: l.logger,
		entry:  l.entry.WithFields(logrus.Fields(fields)),
	}
}

// Helper functions
func parseZapLevel(level string) (zapcore.Level, error) {
	switch strings.ToLower(level) {
	case "debug":
		return zapcore.DebugLevel, nil
	case "info":
		return zapcore.InfoLevel, nil
	case "warn", "warning":
		return zapcore.WarnLevel, nil
	case "error":
		return zapcore.ErrorLevel, nil
	case "fatal":
		return zapcore.FatalLevel, nil
	default:
		return zapcore.InfoLevel, fmt.Errorf("unknown level: %s", level)
	}
}

func parseLogrusLevel(level string) (logrus.Level, error) {
	switch strings.ToLower(level) {
	case "debug":
		return logrus.DebugLevel, nil
	case "info":
		return logrus.InfoLevel, nil
	case "warn", "warning":
		return logrus.WarnLevel, nil
	case "error":
		return logrus.ErrorLevel, nil
	case "fatal":
		return logrus.FatalLevel, nil
	default:
		return logrus.InfoLevel, fmt.Errorf("unknown level: %s", level)
	}
}

func parseFields(fields ...interface{}) logrus.Fields {
	result := make(logrus.Fields)
	
	for i := 0; i < len(fields); i += 2 {
		if i+1 < len(fields) {
			if key, ok := fields[i].(string); ok {
				result[key] = fields[i+1]
			}
		}
	}
	
	return result
}

// Structured logging helpers
type Fields map[string]interface{}

// NewFields creates a new Fields map
func NewFields() Fields {
	return make(Fields)
}

// Add adds a field to the Fields map
func (f Fields) Add(key string, value interface{}) Fields {
	f[key] = value
	return f
}

// AddError adds an error field
func (f Fields) AddError(err error) Fields {
	f["error"] = err.Error()
	return f
}

// AddDuration adds a duration field
func (f Fields) AddDuration(key string, duration interface{}) Fields {
	f[key] = duration
	return f
}

// AddRequestID adds a request ID field
func (f Fields) AddRequestID(requestID string) Fields {
	f["request_id"] = requestID
	return f
}

// AddUserID adds a user ID field
func (f Fields) AddUserID(userID string) Fields {
	f["user_id"] = userID
	return f
}

// AddComponent adds a component field
func (f Fields) AddComponent(component string) Fields {
	f["component"] = component
	return f
}

// AddOperation adds an operation field
func (f Fields) AddOperation(operation string) Fields {
	f["operation"] = operation
	return f
}

// ToMap converts Fields to map[string]interface{}
func (f Fields) ToMap() map[string]interface{} {
	return map[string]interface{}(f)
}

// Common field constants
const (
	FieldRequestID  = "request_id"
	FieldUserID     = "user_id"
	FieldComponent  = "component"
	FieldOperation  = "operation"
	FieldDuration   = "duration"
	FieldError      = "error"
	FieldSentinelID = "sentinel_id"
	FieldThreatID   = "threat_id"
	FieldScanID     = "scan_id"
	FieldAuditID    = "audit_id"
)

// Component constants
const (
	ComponentSentinel   = "sentinel"
	ComponentConsensus  = "consensus"
	ComponentAI         = "ai_engine"
	ComponentHealing    = "healing"
	ComponentServer     = "server"
	ComponentDetector   = "detector"
	ComponentValidator  = "validator"
	ComponentMonitor    = "monitor"
)

// Operation constants
const (
	OperationStartup       = "startup"
	OperationShutdown      = "shutdown"
	OperationHealthCheck   = "health_check"
	OperationThreatDetect  = "threat_detect"
	OperationConfigValidate = "config_validate"
	OperationAuditStart    = "audit_start"
	OperationAuditStop     = "audit_stop"
	OperationMetricsCollect = "metrics_collect"
)