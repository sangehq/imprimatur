// Package contract is the companion contract v1 that sange, CI and other tools
// call (companion-imprimatur.md §4): exit codes 0 to 5, the error document a
// failed --json call prints, and the error type every command returns so its
// exit code and fix line travel with it.
package contract

import (
	"errors"
	"fmt"
	"strings"
)

// Version is the JSON contract version every document carries. Shapes only
// ever gain fields.
const Version = 1

// Code is a defined exit code.
type Code int

// Exit codes.
const (
	OK           Code = 0
	Usage        Code = 1
	Skipped      Code = 2 // only without --strict
	SignFailed   Code = 3
	VerifyFailed Code = 4
	Unavailable  Code = 5
)

// String names the code.
func (c Code) String() string {
	switch c {
	case OK:
		return "ok"
	case Usage:
		return "usage"
	case Skipped:
		return "skipped"
	case SignFailed:
		return "signing failed"
	case VerifyFailed:
		return "verification failed"
	case Unavailable:
		return "unavailable"
	}
	return fmt.Sprintf("exit code %d", int(c))
}

// ExitCodes is the table companion info reports.
func ExitCodes() map[string]int {
	return map[string]int{"ok": 0, "usage": 1, "skipped": 2, "signFailed": 3, "verifyFailed": 4, "unavailable": 5}
}

// Error is a failure the user can act on: what happened, why, and how to fix
// it, with the exit code it maps to.
type Error struct {
	Code    Code
	Message string
	Details []string
	Fix     []string
	cause   error
}

func (e *Error) Error() string {
	if e.cause != nil {
		return e.Message + ": " + e.cause.Error()
	}
	return e.Message
}

// Unwrap returns the cause.
func (e *Error) Unwrap() error { return e.cause }

// New builds an error with a code.
func New(code Code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// Wrap builds an error with a code around a cause.
func Wrap(code Code, cause error, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...), cause: cause}
}

// WithFix adds fix lines.
func (e *Error) WithFix(lines ...string) *Error {
	e.Fix = append(e.Fix, lines...)
	return e
}

// WithDetails adds detail lines.
func (e *Error) WithDetails(lines ...string) *Error {
	e.Details = append(e.Details, lines...)
	return e
}

// CodeOf returns the exit code err maps to: its own code for an *Error, and
// Unavailable for anything else (an I/O failure, a tool that would not start).
func CodeOf(err error) Code {
	if err == nil {
		return OK
	}
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return Unavailable
}

// ErrorBody is the error part of an error document.
type ErrorBody struct {
	Message string   `json:"message"`
	Details []string `json:"details"`
	Fix     []string `json:"fix"`
}

// ErrorDoc is what a failed --json call prints on stdout.
type ErrorDoc struct {
	Contract int       `json:"contract"`
	OK       bool      `json:"ok"`
	ExitCode int       `json:"exitCode"`
	Error    ErrorBody `json:"error"`
}

// DocOf renders err as an error document.
func DocOf(err error) ErrorDoc {
	body := ErrorBody{Message: err.Error(), Details: []string{}, Fix: []string{}}
	var e *Error
	if errors.As(err, &e) {
		body.Message = e.Error()
		body.Details = append(body.Details, e.Details...)
		body.Fix = append(body.Fix, e.Fix...)
	}
	return ErrorDoc{Contract: Version, OK: false, ExitCode: int(CodeOf(err)), Error: body}
}

// Text renders err for a terminal: the message, details and fix lines.
func Text(err error) string {
	var b strings.Builder
	b.WriteString("impr: " + err.Error() + "\n")
	var e *Error
	if errors.As(err, &e) {
		for _, d := range e.Details {
			b.WriteString("  " + d + "\n")
		}
		for _, f := range e.Fix {
			b.WriteString("  fix: " + f + "\n")
		}
	}
	return b.String()
}
