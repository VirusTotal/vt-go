package vt

import (
	"compress/gzip"
	"encoding/json"
	"errors"
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
	status          int
	expectedHeaders map[string]string
	responseHeaders map[string]string
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

func (ts *TestServer) SetStatusCode(s int) *TestServer {
	ts.status = s
	return ts
}

func (ts *TestServer) SetResponseHeader(name, value string) *TestServer {
	if ts.responseHeaders == nil {
		ts.responseHeaders = map[string]string{}
	}
	ts.responseHeaders[name] = value
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
	for name, value := range ts.responseHeaders {
		w.Header().Set(name, value)
	}
	if ts.status != 0 {
		w.WriteHeader(ts.status)
	}
	if ts.status != 429 {
		w.Header().Set("content-encoding", "gzip")
		gw := gzip.NewWriter(w)
		gw.Write(js)
		gw.Close()
	} else {
		w.Write(js)
	}
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

func TestGetObjectOutOfQuota(t *testing.T) {
	ts := NewTestServer(t).
		SetExpectedMethod("GET").
		SetStatusCode(429).
		SetResponse(map[string]interface{}{
			"error": map[string]interface{}{
				"code":    "QuotaExceededError",
				"message": "Quota exceeded",
			},
		})

	defer ts.Close()

	SetHost(ts.URL)
	c := NewClient("apikey")
	_, err := c.GetObject(URL("files/abcabcabcabcabc"))
	if err != nil {
		var vtErr *Error
		if !errors.As(err, &vtErr) && err.(Error).Code != "QuotaExceededError" {
			t.Fatalf("Error getting object from VT: %s", err)
		}
	}
}

func TestGetObjectOutOfQuotaRetryAfter(t *testing.T) {
	ts := NewTestServer(t).
		SetExpectedMethod("GET").
		SetStatusCode(429).
		SetResponseHeader("Retry-After", "120").
		SetResponse(map[string]interface{}{
			"error": map[string]interface{}{
				"code":    "QuotaExceededError",
				"message": "Quota exceeded",
			},
		})

	defer ts.Close()

	SetHost(ts.URL)
	c := NewClient("apikey")
	_, err := c.GetObject(URL("files/abcabcabcabcabc"))
	var vtErr Error
	assert.True(t, errors.As(err, &vtErr))
	assert.Equal(t, "QuotaExceededError", vtErr.Code)
	assert.Equal(t, 120*time.Second, vtErr.RetryAfter)
}

func TestParseRetryAfter(t *testing.T) {
	assert.Equal(t, time.Duration(0), parseRetryAfter(""))
	assert.Equal(t, time.Duration(0), parseRetryAfter("not-a-date"))
	assert.Equal(t, time.Duration(0), parseRetryAfter("-5"))
	assert.Equal(t, 60*time.Second, parseRetryAfter(" 60 "))

	retryAt := time.Now().Add(10 * time.Minute).UTC().Format(http.TimeFormat)
	wait := parseRetryAfter(retryAt)
	assert.True(t, wait > 9*time.Minute && wait <= 10*time.Minute)

	past := time.Now().Add(-time.Minute).UTC().Format(http.TimeFormat)
	assert.Equal(t, time.Duration(0), parseRetryAfter(past))
}

func quotaExceededResponse() map[string]interface{} {
	return map[string]interface{}{
		"error": map[string]interface{}{
			"code":    "QuotaExceededError",
			"message": "Quota exceeded",
		},
	}
}

// countingServer answers with the given handlers in order (repeating the last
// one) and counts the requests received.
func countingServer(t *testing.T, handlers ...http.HandlerFunc) (*httptest.Server, *int) {
	n := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		i := n
		if i >= len(handlers) {
			i = len(handlers) - 1
		}
		n++
		handlers[i](w, r)
	}))
	return ts, &n
}

func respond(status int, retryAfter string, body interface{}) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if retryAfter != "" {
			w.Header().Set("Retry-After", retryAfter)
		}
		w.WriteHeader(status)
		js, _ := json.Marshal(body)
		w.Write(js)
	}
}

func TestNoRetryOn429(t *testing.T) {
	ts, n := countingServer(t, respond(429, "0", quotaExceededResponse()))
	defer ts.Close()
	SetHost(ts.URL)

	c := NewClient("apikey")
	_, err := c.GetObject(URL("files/abc1"))
	var vtErr Error
	assert.True(t, errors.As(err, &vtErr))
	assert.Equal(t, "QuotaExceededError", vtErr.Code)
	assert.Equal(t, 1, *n)
}

func TestEndpointBlockedOn429(t *testing.T) {
	ts, n := countingServer(t,
		respond(429, "3600", quotaExceededResponse()),
		respond(200, "", map[string]interface{}{
			"data": map[string]interface{}{"type": "file", "id": "abc1"},
		}))
	defer ts.Close()
	SetHost(ts.URL)

	c := NewClient("apikey")
	_, err := c.GetObject(URL("files/abc1"))
	var vtErr Error
	assert.True(t, errors.As(err, &vtErr))
	assert.Equal(t, 3600*time.Second, vtErr.RetryAfter)
	assert.Equal(t, 1, *n)

	// The same endpoint with another ID now fails without reaching the API.
	_, err = c.GetObject(URL("files/def2"))
	assert.True(t, errors.As(err, &vtErr))
	assert.Equal(t, "QuotaExceededError", vtErr.Code)
	assert.True(t, vtErr.RetryAfter > 3590*time.Second)
	assert.Equal(t, 1, *n)

	// Other endpoints still reach the API.
	c.GetObject(URL("files/abc1/relationships"))
	assert.Equal(t, 2, *n)
}

func TestQuotaErrorWithoutRetryAfterDoesNotBlock(t *testing.T) {
	ts, n := countingServer(t, respond(429, "", quotaExceededResponse()))
	defer ts.Close()
	SetHost(ts.URL)

	c := NewClient("apikey")
	c.GetObject(URL("files/abc1"))
	c.GetObject(URL("files/abc1"))
	assert.Equal(t, 2, *n)
}

func TestEdge429WithoutRetryAfterBlocksByDefault(t *testing.T) {
	ts, n := countingServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(429)
		w.Write([]byte("<title>429</title>429 Too Many Requests"))
	})
	defer ts.Close()
	SetHost(ts.URL)

	c := NewClient("apikey")
	c.GetObject(URL("files/abc1"))
	_, err := c.GetObject(URL("files/abc1"))
	var vtErr Error
	assert.True(t, errors.As(err, &vtErr))
	assert.Equal(t, "QuotaExceededError", vtErr.Code)
	assert.True(t, vtErr.RetryAfter > 50*time.Second && vtErr.RetryAfter <= 60*time.Second)
	assert.Equal(t, 1, *n)
}

func TestEndpointBlockExpires(t *testing.T) {
	ts, n := countingServer(t, respond(200, "", map[string]interface{}{
		"data": map[string]interface{}{"type": "file", "id": "abc1"},
	}))
	defer ts.Close()
	SetHost(ts.URL)

	c := NewClient("apikey")
	c.block(endpointKey("GET", URL("files/abc1")), -time.Second)
	_, err := c.GetObject(URL("files/abc1"))
	assert.NoError(t, err)
	assert.Equal(t, 1, *n)
}

func TestEndpointKey(t *testing.T) {
	SetHost("https://www.virustotal.com")
	assert.Equal(t, "GET /files/*", endpointKey("get", URL("files/abc1")))
	assert.Equal(t, "GET /files/*/download", endpointKey("GET", URL("files/abc1/download")))
	assert.Equal(t, "GET /domains/*", endpointKey("GET", URL("domains/example.com")))
	assert.Equal(t, "POST /intelligence/retrohunt_jobs", endpointKey("POST", URL("intelligence/retrohunt_jobs")))
	assert.Equal(t, "POST /private/files/*/analyse", endpointKey("POST", URL("private/files/abc1/analyse")))
}
