package vt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCreateCollectionFromRawText(t *testing.T) {
	expected := "{\"data\":{\"type\":\"collection\",\"attributes\":{\"name\":\"test collection\"},\"meta\":{\"raw\":\"hey www.example.com\"}}}"
	ts := NewTestServer(t).
		SetExpectedMethod("POST").
		SetExpectedBody(expected).
		SetResponse(map[string]interface{}{
			"data": map[string]interface{}{
				"type": "collection",
				"id":   "test_id",
				"attributes": map[string]interface{}{
					"name":               "test collection",
					"domains_count":      1,
					"files_count":        0,
					"urls_count":         0,
					"ip_addresses_count": 0,
				},
			},
		})
	defer ts.Close()

	SetHost(ts.URL)
	c := NewClient("api_key")

	builder := NewCollectionBuilder(c)
	builder.AddRawText("hey")
	builder.AddRawText("www.example.com")
	obj, err := builder.PostCollection("test collection")
	assert.NoError(t, err)

	val, err := obj.GetInt64("domains_count")
	assert.NoError(t, err)
	assert.Equal(t, int64(1), val)
}
