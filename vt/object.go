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

func (obj *Object) getAttributeNumber(name string) (json.Number, bool) {
	if attrValue, attrExists := obj.Attributes[name]; attrExists {
		n, isNumber := attrValue.(json.Number)
		return n, isNumber
	}
	return json.Number(""), false
}

func (obj *Object) getContextAttributeNumber(name string) (json.Number, bool) {
	if attrValue, attrExists := obj.ContextAttributes[name]; attrExists {
		n, isNumber := attrValue.(json.Number)
		return n, isNumber
	}
	return json.Number(""), false
}

// GetAttributeInt64 returns an attribute as an int64. It returns the attribute's
// value and a boolean indicating that the attribute exists and is a number.
func (obj *Object) GetAttributeInt64(name string) (int64, bool) {
	n, isNumber := obj.getAttributeNumber(name)
	if isNumber {
		f, err := n.Int64()
		if err == nil {
			return f, true
		}
	}
	return 0, false
}

// GetAttributeFloat64 returns an attribute as a float64. It returns the attribute's
// value and a boolean indicating that the attribute exists and is a number.
func (obj *Object) GetAttributeFloat64(name string) (float64, bool) {
	n, isNumber := obj.getAttributeNumber(name)
	if isNumber {
		f, err := n.Float64()
		if err == nil {
			return f, true
		}
	}
	return 0, false
}

// GetAttributeString returns an attribute as a string. It returns the attribute's
// value and a boolean indicating that the attribute exists and is a string.
func (obj *Object) GetAttributeString(name string) (string, bool) {
	if attrValue, attrExists := obj.Attributes[name]; attrExists {
		s, isString := attrValue.(string)
		return s, isString
	}
	return "", false
}

// GetContextAttributeInt64 returns a context attribute as an int64. It returns
// the attribute's value and a boolean indicating that the context attribute
// exists and is a number.
func (obj *Object) GetContextAttributeInt64(name string) (int64, bool) {
	n, isNumber := obj.getContextAttributeNumber(name)
	if isNumber {
		f, err := n.Int64()
		if err == nil {
			return f, true
		}
	}
	return 0, false
}

// GetContextAttributeFloat64 returns a context attribute as an float64. It
// returns the attribute's value and a boolean indicating that the context
// attribute exists and is a number.
func (obj *Object) GetContextAttributeFloat64(name string) (float64, bool) {
	n, isNumber := obj.getContextAttributeNumber(name)
	if isNumber {
		f, err := n.Float64()
		if err == nil {
			return f, true
		}
	}
	return 0, false
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
