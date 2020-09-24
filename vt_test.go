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

type TestServer struct {
	*httptest.Server
	t              *testing.T
	expectedMethod string
	response       interface{}
}

func NewTestServer(t *testing.T) *TestServer {
	ts := &TestServer{t: t}
	ts.Server = httptest.NewServer(http.HandlerFunc(ts.handler))
	return ts
}

func (ts *TestServer) SetExpectedMethod(m string) *TestServer {
	ts.expectedMethod = m
	return ts
}

func (ts *TestServer) SetResponse(r interface{}) *TestServer {
	ts.response = r
	return ts
}

func (ts *TestServer) handler(w http.ResponseWriter, r *http.Request) {
	if ts.expectedMethod != "" && ts.expectedMethod != r.Method {
		ts.t.Errorf("Unexpected method, expecting %s, got %s",
			ts.expectedMethod, r.Method)
	}
	js, err := json.Marshal(ts.response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	gw := gzip.NewWriter(w)
	gw.Write(js)
	gw.Close()
}

// This tests GET request with passing in a parameter.
func TestGetObject(t *testing.T) {

	ts := NewTestServer(t).
		SetExpectedMethod("GET").
		SetResponse(map[string]interface{}{
			"data": map[string]interface{}{
				"type": "object_type",
				"id":   "object_id",
				"attributes": map[string]interface{}{
					"some_int":    1,
					"some_string": "hello",
					"some_date":   0,
					"some_bool":   true,
					"some_float":  0.1,
					"super": map[string]interface{}{
						"data": 1,
						"complex": map[string]interface{}{
							"data":      true,
							"some_int2": 1234,
						},
					},
					"some_list": []interface{}{
						map[string]interface{}{
							"data": 1,
						},
						map[string]interface{}{
							"data": 2,
						},
					},
				},
				"context_attributes": map[string]interface{}{
					"some_int": 1,
				},
			},
		})

	defer ts.Close()

	vt.SetHost(ts.URL)
	c := vt.NewClient("api_key")
	o, err := c.GetObject(vt.URL("/collection/object_id"))

	assert.NoError(t, err)
	assert.Equal(t, "object_id", o.ID())
	assert.Equal(t, "object_type", o.Type())

	s, err := o.Get("some_string")
	assert.NoError(t, err)
	assert.Equal(t, "hello", s)

	s, err = o.GetString("some_string")
	assert.NoError(t, err)
	assert.Equal(t, "hello", s)

	v, err := o.Get("super.complex.data")
	assert.NoError(t, err)
	assert.Equal(t, true, v)

	v, err = o.Get("super.data")
	assert.NoError(t, err)
	assert.Equal(t, float64(1), v)

	v, err = o.Get("super.complex.some_int2")
	assert.NoError(t, err)
	assert.Equal(t, float64(1234), v)

	v, err = o.Get("some_list.[0].data")
	assert.NoError(t, err)
	assert.Equal(t, float64(1), v)

	assert.ElementsMatch(t,
		[]string{
			"some_int",
			"some_string",
			"some_date",
			"some_bool",
			"some_float",
			"super",
			"some_list",
		},
		o.Attributes())

	assert.ElementsMatch(t,
		[]string{
			"some_int",
		},
		o.ContextAttributes())

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

	_, err = o.Get("complex.non_existing")
	assert.Error(t, err)

	// Testing get after set.
	err = o.Set("some_int", int64(317))
	assert.NoError(t, err)
	assert.Equal(t, int64(317), o.MustGetInt64("some_int"))
	assert.Equal(t, int64(317), o.MustGetInt64("some_int"))
}

func TestPostObject(t *testing.T) {

	ts := NewTestServer(t).
		SetExpectedMethod("POST").
		SetResponse(map[string]interface{}{
			"data": map[string]interface{}{
				"type": "object_type",
				"id":   "object_id",
				"attributes": map[string]interface{}{
					"some_string": "hello",
				},
			},
		})

	defer ts.Close()

	vt.SetHost(ts.URL)
	c := vt.NewClient("api_key")
	o := vt.NewObject("object_type")
	err := c.PostObject(vt.URL("/collection"), o)

	assert.NoError(t, err)
	assert.Equal(t, "object_id", o.ID())
	assert.Equal(t, "object_type", o.Type())
	assert.Equal(t, "hello", o.MustGetString("some_string"))
}

func TestPatchObject(t *testing.T) {

	getServer := NewTestServer(t).
		SetExpectedMethod("GET").
		SetResponse(map[string]interface{}{
			"data": map[string]interface{}{
				"type": "object_type",
				"id":   "object_id",
				"attributes": map[string]interface{}{
					"some_string": "hello",
					"some_int":    1,
				},
			},
		})
	defer getServer.Close()

	patchServer := NewTestServer(t).
		SetExpectedMethod("PATCH").
		SetResponse(map[string]interface{}{
			"data": map[string]interface{}{
				"type": "object_type",
				"id":   "object_id",
				"attributes": map[string]interface{}{
					"some_string": "hello",
				},
			},
		})

	defer patchServer.Close()

	c := vt.NewClient("api_key")

	vt.SetHost(getServer.URL)
	o, err := c.GetObject(vt.URL("/collection/object_id"))

	vt.SetHost(patchServer.URL)
	o.SetString("some_string", "world")
	err = c.PatchObject(vt.URL("/collection/object_id"), o)

	assert.NoError(t, err)
	assert.Equal(t, "object_id", o.ID())
	assert.Equal(t, "object_type", o.Type())
	assert.Equal(t, "hello", o.MustGetString("some_string"))
}

func TestIterator(t *testing.T) {

	ts := NewTestServer(t).
		SetExpectedMethod("GET").
		SetResponse(map[string]interface{}{
			"data": []map[string]interface{}{
				{
					"type": "object_type",
					"id":   "object_id_1",
					"attributes": map[string]interface{}{
						"some_string": "hello",
					},
					"context_attributes": map[string]interface{}{
						"some_string": "foo",
					},
				},
				{
					"type": "object_type",
					"id":   "object_id_2",
					"attributes": map[string]interface{}{
						"some_string": "world",
					},
					"context_attributes": map[string]interface{}{
						"some_string": "bar",
					},
				},
			}})

	defer ts.Close()

	vt.SetHost(ts.URL)
	c := vt.NewClient("api_key")
	it, err := c.Iterator(vt.URL("/collection"))

	assert.NoError(t, err)
	assert.NoError(t, it.Error())

	assert.True(t, it.Next())
	assert.Equal(t, "object_id_1", it.Get().ID())
	s, _ := it.Get().GetContextString("some_string")
	assert.Equal(t, "foo", s)
	assert.True(t, it.Next())
	assert.Equal(t, "object_id_2", it.Get().ID())
	s, _ = it.Get().GetContextString("some_string")
	assert.Equal(t, "bar", s)
	assert.False(t, it.Next())

}

func TestIteratorSingleObject(t *testing.T) {

	ts := NewTestServer(t).
		SetExpectedMethod("GET").
		SetResponse(map[string]interface{}{
			"data": map[string]interface{}{
				"type": "object_type",
				"id":   "object_id",
				"attributes": map[string]interface{}{
					"some_string": "hello",
				},
			},
		})

	defer ts.Close()

	vt.SetHost(ts.URL)
	c := vt.NewClient("api_key")
	it, err := c.Iterator(vt.URL("/collection"))

	assert.NoError(t, err)
	assert.NoError(t, it.Error())

	assert.True(t, it.Next())
	assert.Equal(t, "object_id", it.Get().ID())
	assert.False(t, it.Next())
	assert.Equal(t, "", it.Cursor())
}
