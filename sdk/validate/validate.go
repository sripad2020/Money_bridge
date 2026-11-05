// Package validate is PSTCO-Pay's type and value checkpoint layer.
//
// DecodeStrict parses JSON into a Go value and refuses anything whose JSON
// type does not match the Go field type exactly:
//
//	integer fields  accept only JSON integers: 42, -7. Never 4.0, 4e2, "42", true.
//	float fields    accept only JSON numbers: 1.5, 2, -0.25. Never "1.5", true.
//	bool fields     accept only true or false.
//	string fields   accept only JSON strings.
//	[]byte fields   accept only base64 strings.
//
// It also rejects unknown fields, duplicate keys, trailing data, numbers out
// of the field's range and nesting deeper than 32 levels. On top of the type
// checks, request types implement Checker with value rules built from the
// helpers below (ranges, lengths, allowed values).
package validate

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Error describes one failed checkpoint.
type Error struct {
	Field    string // JSON path, e.g. "records[2]" or "attestation.format"
	Expected string
	Got      string
}

func (e *Error) Error() string {
	if e.Got == "" {
		return fmt.Sprintf("%s: %s", e.Field, e.Expected)
	}
	return fmt.Sprintf("%s: expected %s, got %s", e.Field, e.Expected, e.Got)
}

// IsValidation reports whether err came from a checkpoint.
func IsValidation(err error) bool {
	var e *Error
	return errors.As(err, &e)
}

// Checker is implemented by types with value rules.
type Checker interface {
	Check() error
}

const maxDepth = 32

// DecodeStrict type-checks data against v's type, decodes it, and runs
// v.Check() when v implements Checker.
func DecodeStrict(data []byte, v any) error {
	t := reflect.TypeOf(v)
	if t == nil || t.Kind() != reflect.Pointer {
		return errors.New("validate: DecodeStrict needs a pointer")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := checkValue(dec, t.Elem(), "$", 0); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return &Error{Field: "$", Expected: "a single JSON value", Got: "trailing data"}
	}
	d2 := json.NewDecoder(bytes.NewReader(data))
	d2.DisallowUnknownFields()
	if err := d2.Decode(v); err != nil {
		return &Error{Field: "$", Expected: "valid JSON for the target type", Got: err.Error()}
	}
	if c, ok := v.(Checker); ok {
		return c.Check()
	}
	return nil
}

func tokenKind(tok json.Token) string {
	switch x := tok.(type) {
	case json.Delim:
		if x == '{' {
			return "object"
		}
		if x == '[' {
			return "array"
		}
		return string(x)
	case json.Number:
		if isInteger(string(x)) {
			return "integer " + string(x)
		}
		return "decimal " + string(x)
	case string:
		return "string"
	case bool:
		return "boolean"
	case nil:
		return "null"
	}
	return fmt.Sprintf("%T", tok)
}

func isInteger(s string) bool {
	if s == "" {
		return false
	}
	if s[0] == '-' {
		s = s[1:]
	}
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

var bytesType = reflect.TypeOf([]byte(nil))

func checkValue(dec *json.Decoder, t reflect.Type, path string, depth int) error {
	if depth > maxDepth {
		return &Error{Field: path, Expected: "nesting of at most 32 levels"}
	}
	tok, err := dec.Token()
	if err != nil {
		return &Error{Field: path, Expected: "valid JSON", Got: err.Error()}
	}
	for t.Kind() == reflect.Pointer {
		if tok == nil {
			return nil // explicit null for an optional pointer
		}
		t = t.Elem()
	}
	mismatch := func(want string) error { return &Error{Field: path, Expected: want, Got: tokenKind(tok)} }

	switch t.Kind() {
	case reflect.Interface:
		return skipRest(dec, tok)
	case reflect.Bool:
		if _, ok := tok.(bool); !ok {
			return mismatch("boolean")
		}
	case reflect.String:
		s, ok := tok.(string)
		if !ok {
			return mismatch("string")
		}
		if !utf8.ValidString(s) {
			return &Error{Field: path, Expected: "valid UTF-8"}
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n, ok := tok.(json.Number)
		if !ok || !isInteger(string(n)) {
			return mismatch("integer")
		}
		v, err := strconv.ParseInt(string(n), 10, 64)
		if err != nil || reflect.Zero(t).OverflowInt(v) {
			return &Error{Field: path, Expected: fmt.Sprintf("integer that fits in %s", t.Kind()), Got: string(n)}
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		n, ok := tok.(json.Number)
		if !ok || !isInteger(string(n)) || strings.HasPrefix(string(n), "-") {
			return mismatch("non-negative integer")
		}
		v, err := strconv.ParseUint(string(n), 10, 64)
		if err != nil || reflect.Zero(t).OverflowUint(v) {
			return &Error{Field: path, Expected: fmt.Sprintf("integer that fits in %s", t.Kind()), Got: string(n)}
		}
	case reflect.Float32, reflect.Float64:
		n, ok := tok.(json.Number)
		if !ok {
			return mismatch("number")
		}
		f, err := strconv.ParseFloat(string(n), 64)
		if err != nil || math.IsInf(f, 0) || math.IsNaN(f) || reflect.Zero(t).OverflowFloat(f) {
			return &Error{Field: path, Expected: "finite number", Got: string(n)}
		}
	case reflect.Slice:
		if t == bytesType {
			s, ok := tok.(string)
			if !ok {
				if tok == nil {
					return nil
				}
				return mismatch("base64 string")
			}
			if _, err := base64.StdEncoding.DecodeString(s); err != nil {
				return &Error{Field: path, Expected: "standard base64", Got: "invalid base64"}
			}
			return nil
		}
		if tok == nil {
			return nil
		}
		if d, ok := tok.(json.Delim); !ok || d != '[' {
			return mismatch("array")
		}
		for i := 0; dec.More(); i++ {
			if err := checkValue(dec, t.Elem(), fmt.Sprintf("%s[%d]", path, i), depth+1); err != nil {
				return err
			}
		}
		_, _ = dec.Token() // ]
	case reflect.Map:
		if tok == nil {
			return nil
		}
		if d, ok := tok.(json.Delim); !ok || d != '{' {
			return mismatch("object")
		}
		if t.Key().Kind() != reflect.String {
			return &Error{Field: path, Expected: "map with string keys"}
		}
		seen := map[string]bool{}
		for dec.More() {
			kt, _ := dec.Token()
			k, _ := kt.(string)
			if seen[k] {
				return &Error{Field: path + "." + k, Expected: "unique key", Got: "duplicate key"}
			}
			seen[k] = true
			if err := checkValue(dec, t.Elem(), path+"."+k, depth+1); err != nil {
				return err
			}
		}
		_, _ = dec.Token()
	case reflect.Struct:
		if d, ok := tok.(json.Delim); !ok || d != '{' {
			return mismatch("object")
		}
		fields := structFields(t)
		seen := map[string]bool{}
		for dec.More() {
			kt, _ := dec.Token()
			k, _ := kt.(string)
			if seen[k] {
				return &Error{Field: path + "." + k, Expected: "unique key", Got: "duplicate key"}
			}
			seen[k] = true
			ft, ok := fields[k]
			if !ok {
				return &Error{Field: path + "." + k, Expected: "a known field", Got: "unknown field"}
			}
			if err := checkValue(dec, ft, path+"."+k, depth+1); err != nil {
				return err
			}
		}
		_, _ = dec.Token()
	default:
		return &Error{Field: path, Expected: "supported type", Got: t.Kind().String()}
	}
	return nil
}

func structFields(t reflect.Type) map[string]reflect.Type {
	out := map[string]reflect.Type{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name := f.Name
		if tag, ok := f.Tag.Lookup("json"); ok {
			n, _, _ := strings.Cut(tag, ",")
			if n == "-" {
				continue
			}
			if n != "" {
				name = n
			}
		}
		if f.Anonymous && f.Type.Kind() == reflect.Struct {
			for k, v := range structFields(f.Type) {
				out[k] = v
			}
			continue
		}
		out[name] = f.Type
	}
	return out
}

// skipRest consumes the rest of a value whose first token was tok.
func skipRest(dec *json.Decoder, tok json.Token) error {
	d, ok := tok.(json.Delim)
	if !ok || (d != '{' && d != '[') {
		return nil
	}
	depth := 1
	for depth > 0 {
		t, err := dec.Token()
		if err != nil {
			return err
		}
		if dd, ok := t.(json.Delim); ok {
			switch dd {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
			}
		}
	}
	return nil
}

// ------------------------------------------------------------- value rules

// Int checks min <= v <= max.
func Int(field string, v, min, max int64) error {
	if v < min || v > max {
		return &Error{Field: field, Expected: fmt.Sprintf("integer from %d to %d", min, max), Got: strconv.FormatInt(v, 10)}
	}
	return nil
}

// Float checks a finite number within [min, max].
func Float(field string, v, min, max float64) error {
	if math.IsNaN(v) || math.IsInf(v, 0) || v < min || v > max {
		return &Error{Field: field, Expected: fmt.Sprintf("number from %g to %g", min, max), Got: strconv.FormatFloat(v, 'g', -1, 64)}
	}
	return nil
}

// String checks a string's length in characters and that it has no control characters.
func String(field, v string, min, max int) error {
	n := utf8.RuneCountInString(v)
	if n < min || n > max {
		return &Error{Field: field, Expected: fmt.Sprintf("text of %d to %d characters", min, max), Got: fmt.Sprintf("%d characters", n)}
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return &Error{Field: field, Expected: "text without control characters"}
		}
	}
	return nil
}

// Bytes checks a binary field's length.
func Bytes(field string, v []byte, min, max int) error {
	if len(v) < min || len(v) > max {
		return &Error{Field: field, Expected: fmt.Sprintf("%d to %d bytes", min, max), Got: fmt.Sprintf("%d bytes", len(v))}
	}
	return nil
}

// OneOf checks v is one of the allowed values.
func OneOf(field, v string, allowed ...string) error {
	for _, a := range allowed {
		if v == a {
			return nil
		}
	}
	return &Error{Field: field, Expected: "one of " + strings.Join(allowed, ", "), Got: strconv.Quote(v)}
}

// Digits checks v is n to m decimal digits.
func Digits(field, v string, min, max int) error {
	if len(v) < min || len(v) > max {
		return &Error{Field: field, Expected: fmt.Sprintf("%d to %d digits", min, max)}
	}
	for i := 0; i < len(v); i++ {
		if v[i] < '0' || v[i] > '9' {
			return &Error{Field: field, Expected: "digits only"}
		}
	}
	return nil
}

// Hex checks v is exactly n hex characters.
func Hex(field, v string, n int) error {
	if len(v) != n {
		return &Error{Field: field, Expected: fmt.Sprintf("%d hex characters", n), Got: fmt.Sprintf("%d characters", len(v))}
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return &Error{Field: field, Expected: "lowercase hex"}
		}
	}
	return nil
}

// All returns the first error.
func All(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}
