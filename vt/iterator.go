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
	"compress/flate"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strconv"
	"time"
)

type cursor struct {
	Link   string
	Offset int
}

func (c *cursor) encode() string {
	if c.Link == "" {
		return ""
	}
	var b bytes.Buffer
	b64 := base64.NewEncoder(base64.RawURLEncoding, &b)
	fw, _ := flate.NewWriter(b64, flate.BestCompression)
	json.NewEncoder(fw).Encode(c)
	fw.Close()
	return b.String()
}

func (c *cursor) decode(s string) error {
	if s == "" {
		c.Link = ""
		c.Offset = 0
		return nil
	}
	b := bytes.NewBufferString(s)
	fr := flate.NewReader(base64.NewDecoder(base64.RawURLEncoding, b))
	err := json.NewDecoder(fr).Decode(&c)
	if err != nil {
		return err
	}
	return nil
}

type collectionObject struct {
	object *Object
	cursor cursor
}

// IteratorOptions are the options passed to Iterator.
type IteratorOptions struct {
	// Maximum number of items returned by the iterator.
	Limit int
	// Number of items retrieved on each call to the the API.
	BatchSize int
	// Continuation cursor for starting the iteration where we left.
	Cursor string
	// Filter string. The format for the filter depends on the collection being
	// iterated.
	Filter string
}

// Iterator represents a iterator over a collection of VirusTotal objects.
type Iterator struct {
	client *Client
	ch     chan interface{}
	done   chan bool
	next   *Object
	err    error
	closed bool
	limit  int
	count  int
	cursor string
	links  Links
}

func newIterator(cli *Client, u *url.URL, options IteratorOptions) (*Iterator, error) {

	skip := 0
	it := &Iterator{
		client: cli,
		limit:  options.Limit,
		ch:     make(chan interface{}, 50),
		done:   make(chan bool)}

	if options.Cursor != "" {
		c := cursor{}
		err := c.decode(options.Cursor)
		if err != nil {
			return nil, err
		}
		it.links.Next = c.Link
		skip = c.Offset
	} else {
		q := u.Query()
		if options.BatchSize > 0 {
			q.Add("limit", strconv.Itoa(options.BatchSize))
		}
		if options.Filter != "" {
			q.Add("filter", options.Filter)
		}
		u.RawQuery = q.Encode()
		it.links.Next = u.String()
	}

	go it.iterate(skip)

	return it, nil
}

// Iterator returns an iterator for a collection. Iterators are usually
// used like this:
//
//  cli := vt.Client(<api key>)
//  it, err := cli.Iterator(vt.URL(<collection path>), options)
//  if err != nil {
//	  ...handle error
//  }
//  defer it.Close()
//  for it.Next() {
//    obj := it.Get()
//    ...do something with obj
//  }
//  if err := it.Error(); err != nil {
//    ...handle error
//  }
//
func (cli *Client) Iterator(url *url.URL, options IteratorOptions) (*Iterator, error) {
	return newIterator(cli, url, options)
}

// Next advances the iterator to the next object and returns true if there are
// more objects or false if the end of the collection has been reached.
func (it *Iterator) Next() bool {
	if it.limit > 0 && it.count == it.limit {
		return false
	}
	item, ok := <-it.ch
	if ok {
		switch v := item.(type) {
		case collectionObject:
			it.next = v.object
			it.cursor = v.cursor.encode()
			it.count++
		case error:
			it.next = nil
			it.err = v
		}
	}
	return ok && it.next != nil
}

// Get returns the current object in the collection iterator.
func (it *Iterator) Get() *Object {
	return it.next
}

// Cursor returns a token indicating the current iterator's position.
func (it *Iterator) Cursor() string {
	return it.cursor
}

// Close closes a collection iterator.
func (it *Iterator) Close() {
	if !it.closed {
		it.closed = true
		it.done <- true
	}
}

// Error returns any error occurred during the iteration of a collection.
func (it *Iterator) Error() error {
	return it.err
}

const (
	ok = iota
	retry
	stop
)

func (it *Iterator) trySendToChannel(item interface{}) int {
	select {
	case <-it.done:
		return stop
	case it.ch <- item:
		return ok
	default:
		return retry
	}
}

func (it *Iterator) sendToChannel(item interface{}) int {
	sent := false
	for !sent {
		switch it.trySendToChannel(item) {
		case ok:
			sent = true
		case retry:
			time.Sleep(10 * time.Millisecond)
		case stop:
			return stop
		}
	}
	return ok
}

func (it *Iterator) getMoreObjects() ([]*Object, error) {
	var objs []*Object
	nextURL, err := url.Parse(it.links.Next)
	if err != nil {
		return nil, err
	}
	resp, err := it.client.GetData(nextURL, &objs)
	if err != nil {
		return nil, err
	}
	it.links = resp.Links
	return objs, nil
}

func (it *Iterator) iterate(skip int) {
	sent := 0
loop:
	for it.limit == 0 || sent < it.limit {
		// Send request to the API to get more objects.
		objects, err := it.getMoreObjects()
		if err != nil {
			// If an error occurred send it through the channel
			if it.sendToChannel(err) == stop {
				break loop
			}
		}

		objects = objects[skip:]
		for i, object := range objects {
			co := collectionObject{object: object}
			if i == len(objects)-1 {
				co.cursor.Link = it.links.Next
				co.cursor.Offset = 0
			} else {
				co.cursor.Link = it.links.Self
				co.cursor.Offset = skip + i + 1
			}
			if it.sendToChannel(co) == stop {
				break loop
			}
			sent++
		}

		if len(objects) == 0 || it.links.Next == "" {
			break loop
		}

		skip = 0
	}
	it.closed = true
	close(it.ch)
	close(it.done)
}
