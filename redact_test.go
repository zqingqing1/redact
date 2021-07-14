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

type TestMaps struct {
	Secrets           map[string]string
	SecretPtrs        map[string]*string
	TestStructSecrets map[string]*TestStruct
}

type TestMapList struct {
	Data []*TestMaps
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

func TestStringTestMapAndEmbedded(t *testing.T) {
	t.Run("Should Redact Map And Slice Structs", func(t *testing.T) {
		tMaps := &TestMaps{
			Secrets: map[string]string{
				"secret-key-old": secretVal,
				"secret-key-new": secretVal,
			},
			SecretPtrs: map[string]*string{
				"ptr-secret-key": &secretPtrVal,
			},
			TestStructSecrets: map[string]*TestStruct{
				"ptr-test-struct-key": {
					NonSecret: nonSecretVal,
					Secret:    secretVal,
					SecretPtr: &secretPtrVal,
				},
			},
		}

		err := redact.Redact(tMaps)
		assert.NoError(t, err, "should not fail to redact struct")

		assert.Equal(t, redact.RedactStrConst, tMaps.Secrets["secret-key-old"], "should redact secret value")
		assert.Equal(t, redact.RedactStrConst, tMaps.Secrets["secret-key-new"], "should redact secret value")
		assert.Equal(t, redact.RedactStrConst, *tMaps.SecretPtrs["ptr-secret-key"], "should redact secret value")
		assert.Equal(t, redact.RedactStrConst, tMaps.TestStructSecrets["ptr-test-struct-key"].Secret, "should redact secret value")
		assert.Equal(t, redact.RedactStrConst, *tMaps.TestStructSecrets["ptr-test-struct-key"].SecretPtr, "should redact secret value")
		assert.Equal(t, nonSecretVal, tMaps.TestStructSecrets["ptr-test-struct-key"].NonSecret, "should redact secret value")
	})

	t.Run("Should Redact Map And Slice Structs", func(t *testing.T) {
		tMaps := &TestMaps{
			Secrets: map[string]string{
				"secret-key-old": secretVal,
				"secret-key-new": secretVal,
			},
			SecretPtrs: map[string]*string{
				"ptr-secret-key": &secretPtrVal,
			},
			TestStructSecrets: map[string]*TestStruct{
				"ptr-test-struct-key": {
					NonSecret: nonSecretVal,
					Secret:    secretVal,
					SecretPtr: &secretPtrVal,
				},
			},
		}

		testMapList := &TestMapList{
			Data: []*TestMaps{tMaps},
		}

		err := redact.Redact(testMapList)
		assert.NoError(t, err, "should not fail to redact struct")

		assert.Equal(t, redact.RedactStrConst, testMapList.Data[0].Secrets["secret-key-old"], "should redact secret value")
		assert.Equal(t, redact.RedactStrConst, testMapList.Data[0].Secrets["secret-key-new"], "should redact secret value")
		assert.Equal(t, redact.RedactStrConst, *testMapList.Data[0].SecretPtrs["ptr-secret-key"], "should redact secret value")
		assert.Equal(t, redact.RedactStrConst, testMapList.Data[0].TestStructSecrets["ptr-test-struct-key"].Secret, "should redact secret value")
		assert.Equal(t, redact.RedactStrConst, *testMapList.Data[0].TestStructSecrets["ptr-test-struct-key"].SecretPtr, "should redact secret value")
		assert.Equal(t, nonSecretVal, testMapList.Data[0].TestStructSecrets["ptr-test-struct-key"].NonSecret, "should redact secret value")
	})
}
