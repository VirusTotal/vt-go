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
		var o ObjectDescriptor
		// Try unmarshalling as an ObjectDescriptor first, if it fails this is
		// a one-to-many relationship, so we try unmarshalling as an array of
		// ObjectDescriptor.
		if err := json.Unmarshal(v.Data, &o); err == nil {
			v.IsOneToOne = true
			// If the value is null the ObjectDescriptor will have an empty
			// ID and Type.
			if o.ID == "" && o.Type == "" {
				v.RelatedObjects = nil
			} else {
				v.RelatedObjects = append(v.RelatedObjects, o)
			}
		} else {
			if err := json.Unmarshal(v.Data, &v.RelatedObjects); err != nil {
				return err
			}
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

// GetInt64 returns an attribute as an int64. It returns the attribute's
// value or an error if the attribute doesn't exist or is not a number.
func (obj *Object) GetInt64(name string) (int64, error) {
	n, err := obj.getAttributeNumber(name)
	if err == nil {
		return n.Int64()
	}
	return 0, err
}

// MustGetInt64 is like GetInt64, but it panic in case of error.
func (obj *Object) MustGetInt64(name string) int64 {
	result, err := obj.GetInt64(name)
	if err != nil {
		panic(err)
	}
	return result
}

// GetFloat64 returns an attribute as a float64. It returns the attribute's
// value or an error if the attribute doesn't exist or is not a number.
func (obj *Object) GetFloat64(name string) (float64, error) {
	n, err := obj.getAttributeNumber(name)
	if err == nil {
		return n.Float64()
	}
	return 0, err
}

// MustGetFloat64 is like GetFloat64, but it panic in case of error.
func (obj *Object) MustGetFloat64(name string) float64 {
	result, err := obj.GetFloat64(name)
	if err != nil {
		panic(err)
	}
	return result
}

// GetString returns an attribute as a string. It returns the attribute's
// valueor an error if the attribute doesn't exist or is not a string.
func (obj *Object) GetString(name string) (s string, err error) {
	if attrValue, attrExists := obj.Attributes[name]; attrExists {
		s, isString := attrValue.(string)
		if !isString {
			err = fmt.Errorf("attribute \"%s\" is not a string", name)
		}
		return s, err
	}
	return "", fmt.Errorf("attribute \"%s\" does not exists", name)
}

// MustGetString is like GetString, but it panic in case of error.
func (obj *Object) MustGetString(name string) string {
	result, err := obj.GetString(name)
	if err != nil {
		panic(err)
	}
	return result
}

// GetTime returns an attribute as a time. It returns the attribute's
// value or an error if the attribute doesn't exist or is not a time.
func (obj *Object) GetTime(name string) (t time.Time, err error) {
	n, err := obj.getAttributeNumber(name)
	if err == nil {
		i, err := n.Int64()
		return time.Unix(i, 0), err
	}
	return time.Unix(0, 0), err
}

// MustGetTime is like GetTime, but it panic in case of error.
func (obj *Object) MustGetTime(name string) time.Time {
	result, err := obj.GetTime(name)
	if err != nil {
		panic(err)
	}
	return result
}

// GetBool returns an attribute as a boolean. It returns the attribute's
// value or an error if the attribute doesn't exist or is not a boolean.
func (obj *Object) GetBool(name string) (b bool, err error) {
	if attrValue, attrExists := obj.Attributes[name]; attrExists {
		b, isBool := attrValue.(bool)
		if !isBool {
			err = fmt.Errorf("context attribute \"%s\" is not a bool", name)
		}
		return b, err
	}
	return false, fmt.Errorf("context attribute \"%s\" does not exists", name)
}

// MustGetBool is like GetTime, but it panic in case of error.
func (obj *Object) MustGetBool(name string) bool {
	result, err := obj.GetBool(name)
	if err != nil {
		panic(err)
	}
	return result
}

// GetContextInt64 returns a context attribute as an int64. It returns the
// attribute's value or an error if the attribute doesn't exist or is not a
// number.
func (obj *Object) GetContextInt64(name string) (int64, error) {
	n, err := obj.getContextAttributeNumber(name)
	if err == nil {
		return n.Int64()
	}
	return 0, err
}

// GetContextFloat64 returns a context attribute as an float64. It returns the
// attribute's value or an error if the attribute doesn't exist or is not a
// number.
func (obj *Object) GetContextFloat64(name string) (float64, error) {
	n, err := obj.getContextAttributeNumber(name)
	if err == nil {
		return n.Float64()
	}
	return 0, err
}

// GetContextString returns a context attribute as a string. It returns the
// attribute's value or an error if the attribute doesn't exist or is not a
// string.
func (obj *Object) GetContextString(name string) (s string, err error) {
	if attrValue, attrExists := obj.ContextAttributes[name]; attrExists {
		s, isString := attrValue.(string)
		if !isString {
			err = fmt.Errorf("context attribute \"%s\" is not a string", name)
		}
		return s, err
	}
	return "", fmt.Errorf("context attribute \"%s\" does not exists", name)
}

// GetContextBool returns a context attribute as a bool. It returns the
// attribute's value or an error if the attribute doesn't exist or is not a
// bool.
func (obj *Object) GetContextBool(name string) (b bool, err error) {
	if attrValue, attrExists := obj.ContextAttributes[name]; attrExists {
		b, isBool := attrValue.(bool)
		if !isBool {
			err = fmt.Errorf("context attribute \"%s\" is not a bool", name)
		}
		return b, err
	}
	return false, fmt.Errorf("context attribute \"%s\" does not exists", name)
}
