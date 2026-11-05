package validate

import (
	"strings"
	"testing"
)

type inner struct {
	Ratio float64 `json:"ratio"`
}

type sample struct {
	Count  int64             `json:"count"`
	Small  uint8             `json:"small"`
	Score  float64           `json:"score"`
	Name   string            `json:"name"`
	OK     bool              `json:"ok"`
	Blob   []byte            `json:"blob"`
	List   []int32           `json:"list"`
	Tags   map[string]string `json:"tags"`
	Inner  inner             `json:"inner"`
	Option *int64            `json:"option"`
}

func (s *sample) Check() error { return Int("count", s.Count, 0, 1000) }

func TestStrictTypes(t *testing.T) {
	good := `{"count":42,"small":255,"score":1.5,"name":"x","ok":true,"blob":"AAEC","list":[1,-2],
		"tags":{"a":"b"},"inner":{"ratio":2},"option":null}`
	var s sample
	if err := DecodeStrict([]byte(good), &s); err != nil {
		t.Fatalf("valid document rejected: %v", err)
	}
	if s.Count != 42 || s.Score != 1.5 || s.Inner.Ratio != 2 || len(s.Blob) != 3 {
		t.Fatalf("decoded %+v", s)
	}
	bad := map[string]string{
		"float into integer":       `{"count":4.0}`,
		"exponent into integer":    `{"count":4e2}`,
		"string into integer":      `{"count":"42"}`,
		"bool into integer":        `{"count":true}`,
		"negative into unsigned":   `{"small":-1}`,
		"overflow uint8":           `{"small":256}`,
		"string into float":        `{"score":"1.5"}`,
		"bool into float":          `{"score":false}`,
		"number into string":       `{"name":5}`,
		"number into bool":         `{"ok":1}`,
		"string into bool":         `{"ok":"true"}`,
		"bad base64":               `{"blob":"!!!"}`,
		"decimal in int array":     `{"list":[1,2.5]}`,
		"overflow int32 in array":  `{"list":[3000000000]}`,
		"number in string map":     `{"tags":{"a":1}}`,
		"string into nested float": `{"inner":{"ratio":"2"}}`,
		"unknown field":            `{"count":1,"admin":true}`,
		"duplicate key":            `{"count":1,"count":2}`,
		"trailing data":            `{"count":1} {"count":2}`,
		"array instead of object":  `[1,2]`,
		"value rule":               `{"count":5000}`,
	}
	for name, doc := range bad {
		var s sample
		err := DecodeStrict([]byte(doc), &s)
		if err == nil {
			t.Errorf("%s: accepted %s", name, doc)
			continue
		}
		if !IsValidation(err) {
			t.Errorf("%s: error is not a validation error: %v", name, err)
		}
	}
}

func TestErrorsNameTheField(t *testing.T) {
	var s sample
	err := DecodeStrict([]byte(`{"list":[1,2,"x"]}`), &s)
	if err == nil || !strings.Contains(err.Error(), "list[2]") || !strings.Contains(err.Error(), "integer") {
		t.Fatalf("error %v", err)
	}
}

func TestValueRules(t *testing.T) {
	if String("name", "a\x00b", 1, 10) == nil {
		t.Fatal("control character accepted")
	}
	if Digits("otp", "12a456", 6, 6) == nil || Digits("otp", "123456", 6, 6) != nil {
		t.Fatal("digits rule wrong")
	}
	if Hex("id", "ABCDEF", 6) == nil {
		t.Fatal("uppercase hex accepted")
	}
	if Float("x", 1.0/zero(), 0, 1) == nil {
		t.Fatal("infinity accepted")
	}
}

func zero() float64 { return 0 }
