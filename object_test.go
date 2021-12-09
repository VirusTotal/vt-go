package vt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestModifiedObjectMarshallObject(t *testing.T) {
	obj := NewObject("collection")
	obj.SetData("data_field", "value")
	obj.SetString("name", "collection name")

	modifiedObject := modifiedObject(*obj)
	marshalled, err := modifiedObject.MarshalJSON()
	assert.NoError(t, err)

	assert.Equal(t,
		"{\"attributes\":{\"name\":\"collection name\"},\"data_field\":\"value\",\"type\":\"collection\"}",
		string(marshalled))
}
