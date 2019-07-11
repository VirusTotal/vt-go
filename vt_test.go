package vt_test

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	vt "github.com/VirusTotal/vt-go"
	"github.com/stretchr/testify/assert"
)

func ExampleURL() {
	vt.SetHost("https://www.virustotal.com")
	url := vt.URL("files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
	fmt.Println(url)
	url = vt.URL("intelligence/retrohunt_jobs/%s", "1234567")
	fmt.Println(url)
	// Output:
	// https://www.virustotal.com/api/v3/files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
	// https://www.virustotal.com/api/v3/intelligence/retrohunt_jobs/1234567
}

func createServer(response interface{}) *httptest.Server {
	requestHandler := func(w http.ResponseWriter, r *http.Request) {
		js, err := json.Marshal(response)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		gw := gzip.NewWriter(w)
		gw.Write(js)
		gw.Close()
	}
	return httptest.NewServer(http.HandlerFunc(requestHandler))
}

// This tests GET request with passing in a parameter.
func TestGetObject(t *testing.T) {

	ts := createServer(map[string]interface{}{
		"data": map[string]interface{}{
			"type": "object_type",
			"id":   "object_id",
			"attributes": map[string]interface{}{
				"some_int":    1,
				"some_string": "hello",
				"some_date":   0,
				"some_bool":   true,
				"some_float":  0.1,
			},
		},
	})

	defer ts.Close()

	vt.SetHost(ts.URL)
	c := vt.NewClient("api_key")
	o, err := c.GetObject(vt.URL("/collection/object_id"))

	assert.NoError(t, err)
	assert.Equal(t, "object_id", o.ID)
	assert.Equal(t, "object_type", o.Type)

	assert.Equal(t, int64(1), o.MustGetInt64("some_int"))
	assert.Equal(t, 0.1, o.MustGetFloat64("some_float"))
	assert.Equal(t, "hello", o.MustGetString("some_string"))
	assert.Equal(t, time.Unix(0, 0), o.MustGetTime("some_date"))
	assert.Equal(t, true, o.MustGetBool("some_bool"))

	assert.Panics(t, func() { o.MustGetInt64("some_string") })
	assert.Panics(t, func() { o.MustGetFloat64("some_string") })
	assert.Panics(t, func() { o.MustGetString("some_int") })
	assert.Panics(t, func() { o.MustGetTime("some_string") })
	assert.Panics(t, func() { o.MustGetBool("some_string") })

	_, err = o.GetInt64("non_existing")
	assert.Error(t, err)

	_, err = o.GetFloat64("non_existing")
	assert.Error(t, err)

	_, err = o.GetString("non_existing")
	assert.Error(t, err)

	_, err = o.GetTime("non_existing")
	assert.Error(t, err)

	_, err = o.GetBool("non_existing")
	assert.Error(t, err)
}
