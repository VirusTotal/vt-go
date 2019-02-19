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
	"encoding/json"
	"fmt"
	"time"
)

// ObjectDescriptor is a pair (ID, type) describing a VirusTotal API object.
type ObjectDescriptor struct {
	ID                string                 `json:"id,omitempty"`
	Type              string                 `json:"type,omitempty"`
	ContextAttributes map[string]interface{} `json:"context_attributes,omitempty"`
}

// Object represents a VirusTotal API object.
type Object struct {
	ID                string                   `json:"id,omitempty"`
	Type              string                   `json:"type,omitempty"`
	Attributes        map[string]interface{}   `json:"attributes,omitempty"`
	ContextAttributes map[string]interface{}   `json:"context_attributes,omitempty"`
	Relationships     map[string]*Relationship `json:"relationships,omitempty"`
	Links             Links                    `json:"links,omitempty"`
}

// Links contains links related to an API object.
type Links struct {
	Self string `json:"self"`
	Next string `json:"next"`
}

// Relationship contains information about a related API object.
type Relationship struct {
	Data  json.RawMessage `json:"data,omitempty"`
	Links Links           `json:"links,omitempty"`

	// IsOneToOne is true if this is a one-to-one relationshio and False if
	// otherwise. If true RelatedObjects contains one object at most.
	IsOneToOne     bool
	RelatedObjects []ObjectDescriptor
}

// NewObject creates a new object.
func NewObject() *Object {
	return &Object{Attributes: make(map[string]interface{})}
}

// UnmarshalJSON unmarshals a VirusTotal API object from data.
func (obj *Object) UnmarshalJSON(data []byte) error {

	type object Object

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()

	o := object{}
	if err := decoder.Decode(&o); err != nil {
		return err
	}

	obj.Type = o.Type
	obj.ID = o.ID
	obj.Attributes = o.Attributes
	obj.ContextAttributes = o.ContextAttributes
	obj.Relationships = o.Relationships

	for _, v := range obj.Relationships {
		// Try unmarshalling as an array first, if it fails this is a one-to-one
		// relationship, so we should try unmarshalling a single object descriptor.
		if err := json.Unmarshal(v.Data, &v.RelatedObjects); err != nil {
			v.IsOneToOne = true
			var o ObjectDescriptor
			if err = json.Unmarshal(v.Data, &o); err != nil {
				return err
			}
			v.RelatedObjects = append(v.RelatedObjects, o)
		}
	}

	return nil
}

func (obj *Object) getAttributeNumber(name string) (n json.Number, err error) {
	if attrValue, attrExists := obj.Attributes[name]; attrExists {
		n, isNumber := attrValue.(json.Number)
		if !isNumber {
			err = fmt.Errorf("attribute \"%s\" is not a number", name)
		}
		return n, err
	}
	return n, fmt.Errorf("attribute \"%s\" does not exists", name)
}

func (obj *Object) getContextAttributeNumber(name string) (n json.Number, err error) {
	if attrValue, attrExists := obj.ContextAttributes[name]; attrExists {
		n, isNumber := attrValue.(json.Number)
		if !isNumber {
			err = fmt.Errorf("context attribute \"%s\" is not a number", name)
		}
		return n, err
	}
	return n, fmt.Errorf("context attribute \"%s\" does not exists", name)
}

// GetAttributeInt64 returns an attribute as an int64. It returns the attribute's
// value and a boolean indicating that the attribute exists and is a number.
func (obj *Object) GetAttributeInt64(name string) (int64, error) {
	n, err := obj.getAttributeNumber(name)
	if err == nil {
		return n.Int64()
	}
	return 0, err
}

// GetAttributeFloat64 returns an attribute as a float64. It returns the attribute's
// value and a boolean indicating that the attribute exists and is a number.
func (obj *Object) GetAttributeFloat64(name string) (float64, error) {
	n, err := obj.getAttributeNumber(name)
	if err == nil {
		return n.Float64()
	}
	return 0, err
}

// GetAttributeString returns an attribute as a string. It returns the attribute's
// value and a boolean indicating that the attribute exists and is a string.
func (obj *Object) GetAttributeString(name string) (s string, err error) {
	if attrValue, attrExists := obj.Attributes[name]; attrExists {
		s, isString := attrValue.(string)
		if !isString {
			err = fmt.Errorf("attribute \"%s\" is not a string", name)
		}
		return s, err
	}
	return "", fmt.Errorf("attribute \"%s\" does not exists", name)
}

// GetAttributeTime returns an attribute as a time. It returns the attribute's
// value and a boolean indicating that the attribute exists and is a time.
func (obj *Object) GetAttributeTime(name string) (t time.Time, err error) {
	n, err := obj.getAttributeNumber(name)
	if err == nil {
		i, err := n.Int64()
		return time.Unix(i, 0), err
	}
	return time.Unix(0, 0), err
}

// GetContextAttributeInt64 returns a context attribute as an int64. It returns
// the attribute's value and a boolean indicating that the context attribute
// exists and is a number.
func (obj *Object) GetContextAttributeInt64(name string) (int64, error) {
	n, err := obj.getContextAttributeNumber(name)
	if err == nil {
		return n.Int64()
	}
	return 0, err
}

// GetContextAttributeFloat64 returns a context attribute as an float64. It
// returns the attribute's value and a boolean indicating that the context
// attribute exists and is a number.
func (obj *Object) GetContextAttributeFloat64(name string) (float64, error) {
	n, err := obj.getContextAttributeNumber(name)
	if err == nil {
		return n.Float64()
	}
	return 0, err
}

// GetContextAttributeString returns a context attribute as a string. It returns
// the attribute's svalue and a boolean indicating that the context attribute
// exists and is a string.
func (obj *Object) GetContextAttributeString(name string) (string, bool) {
	if attrValue, attrExists := obj.ContextAttributes[name]; attrExists {
		s, isString := attrValue.(string)
		return s, isString
	}
	return "", false
}
