package vt

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func ExampleURL() {
	SetHost("https://www.virustotal.com")
	url := URL("files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
	fmt.Println(url)
	url = URL("intelligence/retrohunt_jobs/%s", "1234567")
	fmt.Println(url)
	// Output:
	// https://www.virustotal.com/api/v3/files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
	// https://www.virustotal.com/api/v3/intelligence/retrohunt_jobs/1234567
}

type TestServer struct {
	*httptest.Server
	t               *testing.T
	expectedMethod  string
	response        interface{}
	expectedBody    string
	expectedHeaders map[string]string
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

func (ts *TestServer) SetExpectedBody(body string) *TestServer {
	ts.expectedBody = body
	return ts
}

func (ts *TestServer) SetExpectedHeader(header, value string) *TestServer {
	if ts.expectedHeaders == nil {
		ts.expectedHeaders = map[string]string{header: value}
	} else {
		ts.expectedHeaders[header] = value
	}
	return ts
}

func (ts *TestServer) handler(w http.ResponseWriter, r *http.Request) {
	if ts.expectedMethod != "" && ts.expectedMethod != r.Method {
		ts.t.Errorf("Unexpected method, expecting %s, got %s",
			ts.expectedMethod, r.Method)
	}

	if ts.expectedBody != "" {
		data, err := ioutil.ReadAll(r.Body)
		if err != nil {
			ts.t.Errorf("Error reading request data")
		}
		if string(data) != ts.expectedBody {
			ts.t.Errorf("Unexpected request body, expecting %s, got %s",
				ts.expectedBody, string(data))
		}
	}

	if ts.expectedHeaders != nil {
		for k, v := range ts.expectedHeaders {
			if r.Header.Get(k) != v {
				ts.t.Errorf("Missing header '%s: %s' in request", k, v)
			}
		}
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
					"some_tags":   []string{"peexe", "trusted"},
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

	SetHost(ts.URL)
	c := NewClient("api_key")
	o, err := c.GetObject(URL("/collection/object_id"))

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
	assert.Equal(t, json.Number("1"), v)

	v, err = o.Get("super.complex.some_int2")
	assert.NoError(t, err)
	assert.Equal(t, json.Number("1234"), v)

	v, err = o.Get("some_list.[0].data")
	assert.NoError(t, err)
	assert.Equal(t, json.Number("1"), v)

	assert.ElementsMatch(t,
		[]string{
			"some_int",
			"some_string",
			"some_date",
			"some_bool",
			"some_float",
			"some_tags",
			"super",
			"some_list",
		},
		o.Attributes())

	assert.ElementsMatch(t,
		[]string{
			"some_int",
		},
		o.ContextAttributes())

	assert.ElementsMatch(t, o.MustGetStringSlice("some_tags"), []string{"peexe", "trusted"})

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

	_, err = o.GetStringSlice("non_existing")
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

	SetHost(ts.URL)
	c := NewClient("api_key")
	o := NewObject("object_type")
	err := c.PostObject(URL("/collection"), o)

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

	c := NewClient("api_key")

	SetHost(getServer.URL)
	o, err := c.GetObject(URL("/collection/object_id"))
	assert.NoError(t, err)

	SetHost(patchServer.URL)
	o.SetString("some_string", "world")
	err = c.PatchObject(URL("/collection/object_id"), o)

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

	SetHost(ts.URL)
	c := NewClient("api_key")
	it, err := c.Iterator(URL("/collection"))

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

	SetHost(ts.URL)
	c := NewClient("api_key")
	it, err := c.Iterator(URL("/collection"))

	assert.NoError(t, err)
	assert.NoError(t, it.Error())

	assert.True(t, it.Next())
	assert.Equal(t, "object_id", it.Get().ID())
	assert.False(t, it.Next())
	assert.Equal(t, "", it.Cursor())
}

func TestGlobalHeaders(t *testing.T) {

	ts := NewTestServer(t).
		SetExpectedMethod("GET").
		SetExpectedHeader("foo", "bar").
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

	SetHost(ts.URL)
	c := NewClient("api_key", WithGlobalHeader("foo", "bar"))
	_, err := c.GetObject(URL("files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"))
	assert.NoError(t, err)
}

func TestRequestHeadersOverrideGlobalHeaders(t *testing.T) {

	ts := NewTestServer(t).
		SetExpectedMethod("POST").
		SetExpectedHeader("Content-Type", "application/json").
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

	SetHost(ts.URL)
	c := NewClient("api_key", WithGlobalHeader("Content-Type", "bar"))
	o := NewObject("object_type")
	err := c.PostObject(URL("/collection"), o)
	assert.NoError(t, err)
}
