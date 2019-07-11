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

// objectData is the structure that have the data returned by the API for an
// object.
type objectData struct {
	ID                string                   `json:"id,omitempty"`
	Type              string                   `json:"type,omitempty"`
	Attributes        map[string]interface{}   `json:"attributes,omitempty"`
	ContextAttributes map[string]interface{}   `json:"context_attributes,omitempty"`
	Relationships     map[string]*Relationship `json:"relationships,omitempty"`
	Links             *Links                   `json:"links,omitempty"`
}

// Object represents a VirusTotal API object.
type Object struct {
	// Contains the object's data as returned by the API.
	data objectData
	// Contains a list the attributes that have been modified via a call to
	// any of the SetXX methods.
	modifiedAttributes []string
}

// Links contains links related to an API object.
type Links struct {
	Self string `json:"self,omitempty"`
	Next string `json:"next,omitempty"`
}

// Relationship contains information about a related API object.
type Relationship struct {
	Data  json.RawMessage `json:"data,omitempty"`
	Links Links           `json:"links,omitempty"`

	// IsOneToOne is true if this is a one-to-one relationshio and False if
	// otherwise. If true RelatedObjects contains one object at most.
	IsOneToOne     bool
	RelatedObjects []Object
}

// NewObject creates a new object.
func NewObject(objType string) *Object {
	return &Object{data: objectData{
		Type:       objType,
		Attributes: make(map[string]interface{})}}
}

// NewObjectWithID creates a new object with the specified ID.
func NewObjectWithID(objType, id string) *Object {
	return &Object{data: objectData{
		Type:       objType,
		ID:         id,
		Attributes: make(map[string]interface{})}}
}

// ID returns the object's identifier.
func (obj *Object) ID() string {
	return obj.data.ID
}

// Type returns the object's type.
func (obj *Object) Type() string {
	return obj.data.Type
}

// MarshalJSON marshals a VirusTotal API object.
func (obj *Object) MarshalJSON() ([]byte, error) {
	return json.Marshal(obj.data)
}

// UnmarshalJSON unmarshals a VirusTotal API object from data.
func (obj *Object) UnmarshalJSON(data []byte) error {

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()

	od := objectData{}
	if err := decoder.Decode(&od); err != nil {
		return err
	}

	obj.data = od

	for _, v := range obj.data.Relationships {
		var o Object
		// Try unmarshalling as an Object first, if it fails this is a
		// one-to-many relationship, so we try unmarshalling as an array.
		if err := json.Unmarshal(v.Data, &o); err == nil {
			v.IsOneToOne = true
			// If the value is null the ObjectDescriptor will have an empty
			// ID and Type.
			if o.data.ID == "" && o.data.Type == "" {
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
	if attrValue, attrExists := obj.data.Attributes[name]; attrExists {
		n, isNumber := attrValue.(json.Number)
		if !isNumber {
			err = fmt.Errorf("attribute \"%s\" is not a number", name)
		}
		return n, err
	}
	return n, fmt.Errorf("attribute \"%s\" does not exists", name)
}

func (obj *Object) getContextAttributeNumber(name string) (n json.Number, err error) {
	if attrValue, attrExists := obj.data.ContextAttributes[name]; attrExists {
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
	if attrValue, attrExists := obj.data.Attributes[name]; attrExists {
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
	if attrValue, attrExists := obj.data.Attributes[name]; attrExists {
		b, isBool := attrValue.(bool)
		if !isBool {
			err = fmt.Errorf("attribute \"%s\" is not a bool", name)
		}
		return b, err
	}
	return false, fmt.Errorf("attribute \"%s\" does not exists", name)
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
	if attrValue, attrExists := obj.data.ContextAttributes[name]; attrExists {
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
	if attrValue, attrExists := obj.data.ContextAttributes[name]; attrExists {
		b, isBool := attrValue.(bool)
		if !isBool {
			err = fmt.Errorf("context attribute \"%s\" is not a bool", name)
		}
		return b, err
	}
	return false, fmt.Errorf("context attribute \"%s\" does not exists", name)
}

// Set the value for an attribute.
func (obj *Object) set(attr string, value interface{}) error {
	obj.modifiedAttributes = append(obj.modifiedAttributes, attr)
	obj.data.Attributes[attr] = value
	return nil
}

// SetInt64 sets the value of an integer attribute.
func (obj *Object) SetInt64(name string, value int64) error {
	return obj.set(name, value)
}

// SetFloat64 sets the value of an integer attribute.
func (obj *Object) SetFloat64(name string, value float64) error {
	return obj.set(name, value)
}

// SetString sets the value of a string attribute.
func (obj *Object) SetString(name, value string) error {
	return obj.set(name, value)
}

// SetBool sets the value of a string attribute.
func (obj *Object) SetBool(name string, value bool) error {
	return obj.set(name, value)
}

// SetTime sets the value of a time attribute.
func (obj *Object) SetTime(name string, value time.Time) error {
	return obj.set(name, value.Unix())
}

// modifiedObject is a structure exactly like Object, but that implements the
// MarshalJSON interface differently. When a modifiedObject is marshalled as
// JSON only the attributes that has been modified are included. Context
// attributes, relationships and links are not included neither.
type modifiedObject Object

func (obj modifiedObject) MarshalJSON() ([]byte, error) {
	od := objectData{
		ID:         obj.data.ID,
		Type:       obj.data.Type,
		Attributes: make(map[string]interface{}),
	}
	for _, attr := range obj.modifiedAttributes {
		od.Attributes[attr] = obj.data.Attributes[attr]
	}
	return json.Marshal(&od)
}
