// Package jsonstrict rejects structurally ambiguous JSON before typed decoding.
package jsonstrict

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// ErrInvalid is returned for duplicate keys, invalid structure, or trailing values.
var ErrInvalid = errors.New("structurally invalid JSON")

// ai-generated: reject duplicate object keys and trailing JSON values recursively.
func Validate(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := validateValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("%w: trailing data", ErrInvalid)
		}
		return fmt.Errorf("%w: trailing token: %w", ErrInvalid, err)
	}
	return nil
}

// ai-generated: dispatch one JSON value to the relevant structural validator.
func validateValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("%w: read value: %w", ErrInvalid, err)
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		return validateObject(decoder)
	case '[':
		return validateArray(decoder)
	default:
		return fmt.Errorf("%w: unexpected delimiter", ErrInvalid)
	}
}

// ai-generated: validate one object while tracking keys in its own scope.
func validateObject(decoder *json.Decoder) error {
	seen := make(map[string]struct{})
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("%w: read object key: %w", ErrInvalid, err)
		}
		key, ok := keyToken.(string)
		if !ok {
			return fmt.Errorf("%w: object key type", ErrInvalid)
		}
		if _, exists := seen[key]; exists {
			return fmt.Errorf("%w: duplicate key %q", ErrInvalid, key)
		}
		seen[key] = struct{}{}
		if err := validateValue(decoder); err != nil {
			return err
		}
	}
	closing, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("%w: read object terminator: %w", ErrInvalid, err)
	}
	if closing != json.Delim('}') {
		return fmt.Errorf("%w: object terminator", ErrInvalid)
	}
	return nil
}

// ai-generated: recursively validate all values in one array.
func validateArray(decoder *json.Decoder) error {
	for decoder.More() {
		if err := validateValue(decoder); err != nil {
			return err
		}
	}
	closing, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("%w: read array terminator: %w", ErrInvalid, err)
	}
	if closing != json.Delim(']') {
		return fmt.Errorf("%w: array terminator", ErrInvalid)
	}
	return nil
}
