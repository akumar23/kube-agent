package utils

import (
	"errors"
	"fmt"
	"strings"
)

// MultiError aggregates multiple errors into one.
type MultiError struct {
	Errors []error
}

// Error implements the error interface.
func (m *MultiError) Error() string {
	if len(m.Errors) == 0 {
		return "no errors"
	}
	if len(m.Errors) == 1 {
		return m.Errors[0].Error()
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%d errors occurred:", len(m.Errors)))
	for i, err := range m.Errors {
		if i < 10 {
			sb.WriteString(fmt.Sprintf("\n  %d. %v", i+1, err))
		} else if i == 10 {
			sb.WriteString(fmt.Sprintf("\n  ... and %d more", len(m.Errors)-10))
			break
		}
	}
	return sb.String()
}

// Unwrap enables errors.Is/As to inspect individual errors.
func (m *MultiError) Unwrap() []error {
	return m.Errors
}

// Add appends a non-nil error.
func (m *MultiError) Add(err error) {
	if err != nil {
		m.Errors = append(m.Errors, err)
	}
}

// ErrorOrNil returns nil when no errors have been added, otherwise returns m.
func (m *MultiError) ErrorOrNil() error {
	if len(m.Errors) == 0 {
		return nil
	}
	return m
}

// NewMultiError creates a MultiError from a slice, filtering nil entries.
func NewMultiError(errs []error) *MultiError {
	m := &MultiError{Errors: make([]error, 0, len(errs))}
	for _, err := range errs {
		if err != nil {
			m.Errors = append(m.Errors, err)
		}
	}
	return m
}

// CombineErrors returns nil if all inputs are nil, otherwise a MultiError.
func CombineErrors(errs ...error) error {
	return NewMultiError(errs).ErrorOrNil()
}

// RetryableError wraps an error to signal the caller should retry.
type RetryableError struct {
	Err        error
	RetryAfter int // suggested retry delay in seconds
}

// Error implements the error interface.
func (r *RetryableError) Error() string {
	if r.RetryAfter > 0 {
		return fmt.Sprintf("retryable (retry after %ds): %v", r.RetryAfter, r.Err)
	}
	return fmt.Sprintf("retryable: %v", r.Err)
}

// Unwrap returns the underlying error.
func (r *RetryableError) Unwrap() error { return r.Err }

// NewRetryableError wraps err as a retryable error with a suggested delay.
func NewRetryableError(err error, retryAfterSeconds int) *RetryableError {
	return &RetryableError{Err: err, RetryAfter: retryAfterSeconds}
}

// IsRetryable reports whether err (or any error in its chain) is a RetryableError.
func IsRetryable(err error) bool {
	var r *RetryableError
	return errors.As(err, &r)
}

// ErrorWithContext attaches key-value context to an error message.
type ErrorWithContext struct {
	Err     error
	Context map[string]interface{}
}

// Error implements the error interface.
func (e *ErrorWithContext) Error() string {
	var sb strings.Builder
	sb.WriteString(e.Err.Error())
	if len(e.Context) > 0 {
		sb.WriteString(" (")
		first := true
		for k, v := range e.Context {
			if !first {
				sb.WriteString(", ")
			}
			fmt.Fprintf(&sb, "%s: %v", k, v)
			first = false
		}
		sb.WriteString(")")
	}
	return sb.String()
}

// Unwrap returns the underlying error.
func (e *ErrorWithContext) Unwrap() error { return e.Err }

// AddContext attaches a key-value pair to err. If err is already an
// ErrorWithContext, the pair is added to its existing map.
func AddContext(err error, key string, value interface{}) error {
	if err == nil {
		return nil
	}
	var ctxErr *ErrorWithContext
	if errors.As(err, &ctxErr) {
		ctxErr.Context[key] = value
		return ctxErr
	}
	return &ErrorWithContext{
		Err:     err,
		Context: map[string]interface{}{key: value},
	}
}

// WrapErrorf wraps err with a formatted message.
func WrapErrorf(err error, format string, args ...interface{}) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf(format+": %w", append(args, err)...)
}
