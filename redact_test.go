package redact_test

import (
	"testing"

	"github.com/samkreter/redact"
	"github.com/stretchr/testify/assert"
)

const (
	snapshotVal    = "thisIsASnapShotVal"
	nonSnapshotVal = "thisIsNotASnapshotVal"
)

var (
	snapshotPtrVal    = "thisIsAPtrSnapshot"
	nonSnapshotPtrVal = "thisIsNotPtrSnapshot"
)

type TestStruct struct {
	NonSnapshot    string
	NonSnapshotPtr *string
	SnapshotStr    string  `redact:"snapshot"`
	SnapshotStrPtr *string `redact:"snapshot"`
}

type TestStructList struct {
	Data []*TestStruct
}

type TestStructEmbed struct {
	data TestStruct `redact:"snapshot"`
}

type TestMaps struct {
	NonSnapshotMap    map[string]string
	NonSnapshotMapPtr map[string]*string
	TestStructs       map[string]*TestStruct
}

type TestMapList struct {
	Data []*TestMaps
}

func TestStringTestStruct(t *testing.T) {
	t.Run("Basic Snapshot Redaction", func(t *testing.T) {
		tStruct := &TestStruct{
			NonSnapshot:    nonSnapshotVal,
			NonSnapshotPtr: &nonSnapshotPtrVal,
			SnapshotStr:    snapshotVal,
			SnapshotStrPtr: &snapshotPtrVal,
		}

		err := redact.Snapshot(tStruct)
		assert.NoError(t, err, "should not fail to redact struct")

		assert.Equal(t, snapshotVal, tStruct.SnapshotStr, "should contain snapshot value")
		assert.Equal(t, snapshotPtrVal, *tStruct.SnapshotStrPtr, "should contain snapshot value")
		assert.Equal(t, redact.RedactStrConst, tStruct.NonSnapshot, "should redact non snapshot value")
		assert.Equal(t, redact.RedactStrConst, *tStruct.NonSnapshotPtr, "should redact non snapshot pointer value")
	})

	t.Run("Should still redact empty non snapshot strings", func(t *testing.T) {
		emptyStrVal := ""

		tStruct := &TestStruct{
			NonSnapshot:    "",
			NonSnapshotPtr: &emptyStrVal,
			SnapshotStr:    snapshotVal,
		}

		err := redact.Snapshot(tStruct)
		assert.NoError(t, err, "should not fail to redact struct")

		assert.Equal(t, snapshotVal, tStruct.SnapshotStr, "should contain snapshot value")
		assert.Equal(t, redact.RedactStrConst, tStruct.NonSnapshot, "should redact non snapshot value")
		assert.Equal(t, redact.RedactStrConst, *tStruct.NonSnapshotPtr, "should redact non snapshot value")
	})

}

func TestStringTestStructList(t *testing.T) {
	t.Run("Basic Snapshot Redaction", func(t *testing.T) {
		tStruct := &TestStruct{
			NonSnapshot:    nonSnapshotVal,
			NonSnapshotPtr: &nonSnapshotPtrVal,
			SnapshotStr:    snapshotVal,
			SnapshotStrPtr: &snapshotPtrVal,
		}

		list := &TestStructList{
			Data: []*TestStruct{tStruct},
		}

		err := redact.Snapshot(list)
		assert.NoError(t, err, "should not fail to redact struct")

		assert.Equal(t, snapshotVal, list.Data[0].SnapshotStr, "should contain snapshot value")
		assert.Equal(t, snapshotPtrVal, *list.Data[0].SnapshotStrPtr, "should contain snapshot value")
		assert.Equal(t, redact.RedactStrConst, list.Data[0].NonSnapshot, "should redact non snapshot value")
		assert.Equal(t, redact.RedactStrConst, *list.Data[0].NonSnapshotPtr, "should redact non snapshot value")
	})

	t.Run("Should still redact empty strings", func(t *testing.T) {
		emptyStrVal := ""

		tStruct := &TestStruct{
			NonSnapshot:    "",
			NonSnapshotPtr: &emptyStrVal,
			SnapshotStr:    snapshotVal,
		}

		list := &TestStructList{
			Data: []*TestStruct{tStruct},
		}

		err := redact.Snapshot(list)
		assert.NoError(t, err, "should not fail to redact struct")

		assert.Equal(t, snapshotVal, list.Data[0].SnapshotStr, "should contain snapshot value")
		assert.Equal(t, redact.RedactStrConst, list.Data[0].NonSnapshot, "should redact non snapshot value")
		assert.Equal(t, redact.RedactStrConst, *list.Data[0].NonSnapshotPtr, "should redact non snapshot value")
	})

}

func TestStringTestMapAndEmbedded(t *testing.T) {
	t.Run("Should Redact Map Structs", func(t *testing.T) {
		tMaps := &TestMaps{
			NonSnapshotMap: map[string]string{
				"secret-key-old": nonSnapshotVal,
				"secret-key-new": nonSnapshotVal,
			},
			NonSnapshotMapPtr: map[string]*string{
				"ptr-secret-key": &nonSnapshotPtrVal,
			},
			TestStructs: map[string]*TestStruct{
				"ptr-test-struct-key": {
					NonSnapshot:    nonSnapshotVal,
					NonSnapshotPtr: &nonSnapshotPtrVal,
					SnapshotStr:    snapshotVal,
					SnapshotStrPtr: &snapshotPtrVal,
				},
			},
		}

		err := redact.Snapshot(tMaps)
		assert.NoError(t, err, "should not fail to redact struct")

		assert.Equal(t, redact.RedactStrConst, tMaps.NonSnapshotMap["secret-key-old"], "should redact non snapshot value")
		assert.Equal(t, redact.RedactStrConst, tMaps.NonSnapshotMap["secret-key-new"], "should redact non snapshot value")
		assert.Equal(t, redact.RedactStrConst, *tMaps.NonSnapshotMapPtr["ptr-secret-key"], "should redact non snapshot value")
		assert.Equal(t, redact.RedactStrConst, tMaps.TestStructs["ptr-test-struct-key"].NonSnapshot, "should redact non snapshot value")
		assert.Equal(t, redact.RedactStrConst, *tMaps.TestStructs["ptr-test-struct-key"].NonSnapshotPtr, "should redact non snapshot value")
		assert.Equal(t, snapshotVal, tMaps.TestStructs["ptr-test-struct-key"].SnapshotStr, "should contain snapshot value")
		assert.Equal(t, snapshotPtrVal, *tMaps.TestStructs["ptr-test-struct-key"].SnapshotStrPtr, "should contain snapshot value")
	})

	t.Run("Should Redact Map And Slice Structs", func(t *testing.T) {
		tMaps := &TestMaps{
			NonSnapshotMap: map[string]string{
				"secret-key-old": nonSnapshotVal,
				"secret-key-new": nonSnapshotVal,
			},
			NonSnapshotMapPtr: map[string]*string{
				"ptr-secret-key": &nonSnapshotPtrVal,
			},
			TestStructs: map[string]*TestStruct{
				"ptr-test-struct-key": {
					NonSnapshot:    nonSnapshotVal,
					NonSnapshotPtr: &nonSnapshotPtrVal,
					SnapshotStr:    snapshotVal,
				},
			},
		}

		testMapList := &TestMapList{
			Data: []*TestMaps{tMaps},
		}

		err := redact.Snapshot(testMapList)
		assert.NoError(t, err, "should not fail to redact struct")

		assert.Equal(t, redact.RedactStrConst, testMapList.Data[0].NonSnapshotMap["secret-key-old"], "should redact non snapshot value")
		assert.Equal(t, redact.RedactStrConst, testMapList.Data[0].NonSnapshotMap["secret-key-new"], "should redact non snapshot value")
		assert.Equal(t, redact.RedactStrConst, *testMapList.Data[0].NonSnapshotMapPtr["ptr-secret-key"], "should redact non snapshot value")
		assert.Equal(t, redact.RedactStrConst, testMapList.Data[0].TestStructs["ptr-test-struct-key"].NonSnapshot, "should redact non snapshot value")
		assert.Equal(t, redact.RedactStrConst, *testMapList.Data[0].TestStructs["ptr-test-struct-key"].NonSnapshotPtr, "should redact non snapshot value")
		assert.Equal(t, snapshotVal, testMapList.Data[0].TestStructs["ptr-test-struct-key"].SnapshotStr, "should redact non snapshot value")
	})
}

func TestStringTestStructAndEmbed(t *testing.T) {
	t.Run("snapshot a struct, all of the value from the struct is snapshoted", func(t *testing.T) {
		tStruct := TestStruct{
			NonSnapshot:    nonSnapshotVal,
			NonSnapshotPtr: &nonSnapshotPtrVal,
			SnapshotStr:    snapshotVal,
			SnapshotStrPtr: &snapshotPtrVal,
		}

		embed := &TestStructEmbed{
			data: tStruct,
		}

		err := redact.Snapshot(embed)
		assert.NoError(t, err, "should not fail to redact struct")

		assert.Equal(t, snapshotVal, embed.data.SnapshotStr, "should contain snapshot value")
		assert.Equal(t, snapshotPtrVal, *embed.data.SnapshotStrPtr, "should contain snapshot value")
		assert.Equal(t, nonSnapshotVal, embed.data.NonSnapshot, "should redact non snapshot value")
		assert.Equal(t, nonSnapshotPtrVal, *embed.data.NonSnapshotPtr, "should redact non snapshot value")
	})
}
