package redact_test

import (
	"testing"

	"github.com/samkreter/redact"
	"github.com/stretchr/testify/assert"
)

const (
	secretVal    = "thisIsASecret"
	nonSecretVal = "thisIsAStandardVal"
)

var (
	secretPtrVal = "thisIsAPtrSecret"
)

type TestStruct struct {
	Secret    string
	SecretPtr *string
	NonSecret string `redact:"nonsecret"`
}

type TestStructList struct {
	Data []*TestStruct
}

func TestStringTestStruct(t *testing.T) {
	t.Run("Basic Secret Redaction", func(t *testing.T) {
		tStruct := &TestStruct{
			NonSecret: nonSecretVal,
			Secret:    secretVal,
			SecretPtr: &secretPtrVal,
		}

		err := redact.Redact(tStruct)
		assert.NoError(t, err, "should not fail to redact struct")

		assert.Equal(t, nonSecretVal, tStruct.NonSecret, "should contain non secret value")
		assert.Equal(t, redact.RedactStrConst, tStruct.Secret, "should redact secret value")
		assert.Equal(t, redact.RedactStrConst, *tStruct.SecretPtr, "should redact secret value")
	})

	t.Run("Should still redact empty strings", func(t *testing.T) {
		emptyStrVal := ""

		tStruct := &TestStruct{
			NonSecret: nonSecretVal,
			Secret:    "",
			SecretPtr: &emptyStrVal,
		}

		err := redact.Redact(tStruct)
		assert.NoError(t, err, "should not fail to redact struct")

		assert.Equal(t, nonSecretVal, tStruct.NonSecret, "should contain non secret value")
		assert.Equal(t, redact.RedactStrConst, tStruct.Secret, "should redact secret value")
		assert.Equal(t, redact.RedactStrConst, *tStruct.SecretPtr, "should redact secret value")
	})

}

func TestStringTestStructList(t *testing.T) {
	t.Run("Basic Secret Redaction", func(t *testing.T) {
		tStruct := &TestStruct{
			NonSecret: nonSecretVal,
			Secret:    secretVal,
			SecretPtr: &secretPtrVal,
		}

		list := &TestStructList{
			Data: []*TestStruct{tStruct},
		}

		err := redact.Redact(list)
		assert.NoError(t, err, "should not fail to redact struct")

		assert.Equal(t, nonSecretVal, list.Data[0].NonSecret, "should contain non secret value")
		assert.Equal(t, redact.RedactStrConst, list.Data[0].Secret, "should redact secret value")
		assert.Equal(t, redact.RedactStrConst, *list.Data[0].SecretPtr, "should redact secret value")
	})

	t.Run("Should still redact empty strings", func(t *testing.T) {
		emptyStrVal := ""

		tStruct := &TestStruct{
			NonSecret: nonSecretVal,
			Secret:    "",
			SecretPtr: &emptyStrVal,
		}

		list := &TestStructList{
			Data: []*TestStruct{tStruct},
		}

		err := redact.Redact(list)
		assert.NoError(t, err, "should not fail to redact struct")

		assert.Equal(t, nonSecretVal, list.Data[0].NonSecret, "should contain non secret value")
		assert.Equal(t, redact.RedactStrConst, list.Data[0].Secret, "should redact secret value")
		assert.Equal(t, redact.RedactStrConst, *list.Data[0].SecretPtr, "should redact secret value")
	})

}
