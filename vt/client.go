// Copyright © 2017 The vt-go authors. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package vt

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Client for interacting with VirusTotal API.
type Client struct {
	APIKey     string
	httpClient *http.Client
}

// NewClient creates a new client for interacting with the VirusTotal API using
// the provided API key.
func NewClient(APIKey string) *Client {
	return &Client{APIKey: APIKey, httpClient: &http.Client{}}
}

// sendRequest sends a HTTP request to the VirusTotal REST API.
func (cli *Client) sendRequest(method string, url *url.URL, body io.Reader, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequest(method, url.String(), body)
	if err != nil {
		return nil, err
	}
	// AppEngine server decides whether or not it should serve gzipped content
	// based on Accept-Encoding and User-Agent. Non-standard UAs are not served
	// with gzipped content unless it contains the string "gzip" somewhere.
	// See: https://cloud.google.com/appengine/kb/#compression
	req.Header.Set("User-Agent", fmt.Sprintf("vtgo %s; gzip", version))
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("X-Apikey", cli.APIKey)

	if headers != nil {
		for k, v := range headers {
			req.Header.Set(k, v)
		}
	}

	return (cli.httpClient).Do(req)
}

// parseResponse parses a HTTP response received from the VirusTotal REST API.
// If a valid JSON response was received from the server this function returns
// a pointer to a Response structure. An error is returned either if the response
// was not a valid JSON or if it was a valid JSON but contained an API error.
// Notice that this means that both return values can be non-nil.
func (cli *Client) parseResponse(resp *http.Response) (*Response, error) {

	apiresp := &Response{}

	if resp.ContentLength == 0 {
		return apiresp, nil
	}

	// If the response has some content its format should be JSON
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		return nil, fmt.Errorf("Expecting JSON response from %s %s",
			resp.Request.Method, resp.Request.URL.String())
	}

	// Prepare gzip reader for uncompressing gzipped JSON response
	ungzipper, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, err
	}
	defer ungzipper.Close()

	if err := json.NewDecoder(ungzipper).Decode(apiresp); err != nil {
		return nil, err
	}

	// Check if the response was an error
	if apiresp.Error.Code != "" {
		return apiresp, apiresp.Error
	}

	return apiresp, nil
}

// Get sends a GET request to the specified API endpoint.
func (cli *Client) Get(url *url.URL) (*Response, error) {
	httpResp, err := cli.sendRequest("GET", url, nil, nil)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()
	return cli.parseResponse(httpResp)
}

// Post sends a POST request to the specified API endpoint.
func (cli *Client) Post(url *url.URL, req *Request) (*Response, error) {
	var b []byte
	var err error
	if req != nil {
		b, err = json.Marshal(req)
		if err != nil {
			return nil, err
		}
	}
	httpResp, err := cli.sendRequest("POST", url, bytes.NewReader(b), nil)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()
	return cli.parseResponse(httpResp)
}

// Patch sends a PATCH request to the specified API endpoint.
func (cli *Client) Patch(url *url.URL, req *Request) (*Response, error) {
	var b []byte
	var err error
	if req != nil {
		b, err = json.Marshal(req)
		if err != nil {
			return nil, err
		}
	}
	httpResp, err := cli.sendRequest("PATCH", url, bytes.NewReader(b), nil)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()
	return cli.parseResponse(httpResp)
}

// Delete sends a DELETE request to the specified API endpoint.
func (cli *Client) Delete(url *url.URL) (*Response, error) {
	httpResp, err := cli.sendRequest("DELETE", url, nil, nil)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()
	return cli.parseResponse(httpResp)
}

// GetData sends a GET request to the specified API endpoint and unmarshals the
// JSON-encoded data received in the API response. The unmarshalled data is put
// into the specified target. The target must be of an appropriate type capable
// of receiving the data returned by the the endpoint.
func (cli *Client) GetData(url *url.URL, target interface{}) (*Response, error) {
	resp, err := cli.Get(url)
	if err != nil {
		return nil, err
	}
	return resp, json.Unmarshal(resp.Data, target)
}

// GetObject returns an Object from a path. The specified path must reference
// an object, not a collection. This means that GetObject can be used with paths
// like /files/{file_id} and /urls/{url_id}, which return an individual object
// but not with /comments, which returns a collection of objects.
func (cli *Client) GetObject(url *url.URL) (*Object, error) {
	obj := &Object{}
	if _, err := cli.GetData(url, obj); err != nil {
		return nil, err
	}
	return obj, nil
}

// CreateObject adds an Object to a collection. The specified path must reference
// a collection, not an object, but not all collections accept this operation.
func (cli *Client) CreateObject(url *url.URL, obj *Object) error {
	req := &Request{}
	req.Data = obj
	resp, err := cli.Post(url, req)
	if err != nil {
		return err
	}
	return json.Unmarshal(resp.Data, obj)
}

// PatchObject modifies an existing object.
func (cli *Client) PatchObject(url *url.URL, obj *Object) error {
	req := &Request{}
	req.Data = obj
	resp, err := cli.Patch(url, req)
	if err != nil {
		return err
	}
	return json.Unmarshal(resp.Data, obj)
}

// DownloadFile downloads a file given its hash (SHA-256, SHA-1 or MD5). The
// file is written into the provided io.Writer.
func (cli *Client) DownloadFile(hash string, w io.Writer) (int64, error) {
	u := URL("files/%s/download", hash)
	resp, err := cli.sendRequest("GET", u, nil, nil)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return io.Copy(w, resp.Body)
}

// SearchOptions is a structure with options for Search.
type SearchOptions struct {
	IteratorOptions
	DescriptorsOnly bool
}

// Search for files using VirusTotal Intelligence query language.
func (cli *Client) Search(query string, options SearchOptions) (*Iterator, error) {
	u := URL("intelligence/search")
	q := u.Query()
	q.Add("query", query)
	if options.DescriptorsOnly {
		q.Add("descriptors_only", "true")
	}
	u.RawQuery = q.Encode()
	return newIterator(cli, u, options.IteratorOptions)
}

// Metadata describes the structure returned by /api/v3/metadata with metadata
// about VirusTotal, including the relationships supported by each object type.
type Metadata struct {
	Engines       map[string]interface{}        `json:"engines" yaml:"engines"`
	Relationships map[string][]RelationshipMeta `json:"relationships" yaml:"relationships"`
	Privileges    []string                      `json:"privileges" yaml:"privileges"`
}

// RelationshipMeta is the structure returned by each relationship from the
// /api/v3/metadata endpoint.
type RelationshipMeta struct {
	Name        string `json:"name" yaml:"name"`
	Description string `json:"description" yaml:"description"`
}

// GetMetadata retrieves VirusTotal metadata by calling the /api/v3/metadata
// endpoint.
func (cli *Client) GetMetadata() (*Metadata, error) {
	metadata := &Metadata{}
	if _, err := cli.GetData(URL("metadata"), metadata); err != nil {
		return nil, err
	}
	return metadata, nil
}

// NewFileScanner returns a new FileScanner.
func (cli *Client) NewFileScanner() *FileScanner {
	return &FileScanner{cli: cli}
}

// NewURLScanner returns a new URLScanner.
func (cli *Client) NewURLScanner() *URLScanner {
	return &URLScanner{cli: cli}
}
