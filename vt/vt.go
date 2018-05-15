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

/*
Package vt is a client library for the VirusTotal API
*/
package vt

import (
	"encoding/json"
	"fmt"
	"net/url"
)

const (
	version = "0.1"
)

const (
	apiScheme      = "https"
	apiHost        = "www.virustotal.com"
	apiPrefix      = "api/v3/"
	payloadMaxSize = 30 * 1024 * 1024 // 30 MB
)

var baseURL = url.URL{
	Scheme: apiScheme,
	Host:   apiHost,
	Path:   apiPrefix}

// Request is the top level structure of an API request.
type Request struct {
	Data interface{} `json:"data"`
}

// Response is the top level structure of an API response.
type Response struct {
	Data  json.RawMessage `json:"data"`
	Links Links           `json:"links"`
	Error Error           `json:"error"`
}

// Error contains information about an API error.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Error implements the error interface.
func (e Error) Error() string {
	return e.Message
}

// URL returns a full VirusTotal API URL from a relative path (i.e: API paths
// without the domain name and the "/api/v3" prefix). This function is useful
// for creating URLs to be passed to all function expecting a *url.URL in this
// library.
func URL(pathFmt string, a ...interface{}) *url.URL {
	path := fmt.Sprintf(pathFmt, a...)
	url, _ := url.Parse(path)
	return baseURL.ResolveReference(url)
}
