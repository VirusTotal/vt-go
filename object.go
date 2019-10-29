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
	ID                string                       `json:"id,omitempty"`
	Type              string                       `json:"type,omitempty"`
	Attributes        map[string]interface{}       `json:"attributes,omitempty"`
	ContextAttributes map[string]interface{}       `json:"context_attributes,omitempty"`
	Relationships     map[string]*relationshipData `json:"relationships,omitempty"`
	Links             *Links                       `json:"links,omitempty"`
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

// Attributes returns a list with the names of the object's attributes.
func (obj *Object) Attributes() []string {
	result := make([]string, len(obj.data.Attributes))
	i := 0
	for attr := range obj.data.Attributes {
		result[i] = attr
		i++
	}
	return result
}

// ContextAttributes returns a list with the names of the object's context
// attributes. Context attributes are additional attributes that only make
// sense in a specific context. For example, when retrieving objects that
// are part of a relationship, the objects may have attributes that only make
// sense in the context of that relationship.
func (obj *Object) ContextAttributes() []string {
	result := make([]string, len(obj.data.ContextAttributes))
	i := 0
	for attr := range obj.data.ContextAttributes {
		result[i] = attr
		i++
	}
	return result
}

// Relationships returns a list with the names of the object's relationships.
func (obj *Object) Relationships() []string {
	result := make([]string, len(obj.data.Relationships))
	i := 0
	for rel := range obj.data.Relationships {
		result[i] = rel
		i++
	}
	return result
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
			// If the value is null the Object will have an empty ID and Type.
			if o.data.ID == "" && o.data.Type == "" {
				v.Objects = nil
			} else {
				v.Objects = append(v.Objects, &o)
			}
		} else {
			if err := json.Unmarshal(v.Data, &v.Objects); err != nil {
				return err
			}
		}
	}

	return nil
}

func (obj *Object) getAttributeNumber(attr string) (json.Number, error) {
	value, err := obj.Get(attr)
	if err != nil {
		return "", err
	}
	n, isNumber := value.(json.Number)
	if !isNumber {
		err = fmt.Errorf("context attribute \"%s\" is not a number", attr)
	}
	return n, err
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

// Get an attribute by name.
func (obj *Object) Get(attr string) (interface{}, error) {
	if value, exists := obj.data.Attributes[attr]; exists {
		return value, nil
	}
	return nil, fmt.Errorf("attribute \"%s\" does not exists", attr)
}

// GetInt64 returns an attribute as an int64. It returns the attribute's
// value or an error if the attribute doesn't exist or is not a number.
func (obj *Object) GetInt64(attr string) (int64, error) {
	n, err := obj.getAttributeNumber(attr)
	if err == nil {
		return n.Int64()
	}
	return 0, err
}

// MustGetInt64 is like GetInt64, but it panic in case of error.
func (obj *Object) MustGetInt64(attr string) int64 {
	result, err := obj.GetInt64(attr)
	if err != nil {
		panic(err)
	}
	return result
}

// GetFloat64 returns an attribute as a float64. It returns the attribute's
// value or an error if the attribute doesn't exist or is not a number.
func (obj *Object) GetFloat64(attr string) (float64, error) {
	n, err := obj.getAttributeNumber(attr)
	if err == nil {
		return n.Float64()
	}
	return 0, err
}

// MustGetFloat64 is like GetFloat64, but it panic in case of error.
func (obj *Object) MustGetFloat64(attr string) float64 {
	result, err := obj.GetFloat64(attr)
	if err != nil {
		panic(err)
	}
	return result
}

// GetString returns an attribute as a string. It returns the attribute's
// valueor an error if the attribute doesn't exist or is not a string.
func (obj *Object) GetString(attr string) (s string, err error) {
	value, err := obj.Get(attr)
	if err != nil {
		return s, err
	}
	s, isString := value.(string)
	if !isString {
		err = fmt.Errorf("attribute \"%s\" is not a string", attr)
	}
	return s, err
}

// MustGetString is like GetString, but it panic in case of error.
func (obj *Object) MustGetString(attr string) string {
	result, err := obj.GetString(attr)
	if err != nil {
		panic(err)
	}
	return result
}

// GetTime returns an attribute as a time. It returns the attribute's
// value or an error if the attribute doesn't exist or is not a time.
func (obj *Object) GetTime(attr string) (t time.Time, err error) {
	n, err := obj.getAttributeNumber(attr)
	if err == nil {
		i, err := n.Int64()
		return time.Unix(i, 0), err
	}
	return time.Unix(0, 0), err
}

// MustGetTime is like GetTime, but it panic in case of error.
func (obj *Object) MustGetTime(attr string) time.Time {
	result, err := obj.GetTime(attr)
	if err != nil {
		panic(err)
	}
	return result
}

// GetBool returns an attribute as a boolean. It returns the attribute's
// value or an error if the attribute doesn't exist or is not a boolean.
func (obj *Object) GetBool(attr string) (b bool, err error) {
	value, err := obj.Get(attr)
	if err != nil {
		return b, err
	}
	b, isBool := value.(bool)
	if !isBool {
		err = fmt.Errorf("attribute \"%s\" is not a bool", attr)
	}
	return b, err
}

// MustGetBool is like GetTime, but it panic in case of error.
func (obj *Object) MustGetBool(attr string) bool {
	result, err := obj.GetBool(attr)
	if err != nil {
		panic(err)
	}
	return result
}

// GetContext gets a context attribute by name.
func (obj *Object) GetContext(attr string) (interface{}, error) {
	if value, exists := obj.data.ContextAttributes[attr]; exists {
		return value, nil
	}
	return nil, fmt.Errorf("context attribute \"%s\" does not exists", attr)
}

// GetContextInt64 returns a context attribute as an int64. It returns the
// attribute's value or an error if the attribute doesn't exist or is not a
// number.
func (obj *Object) GetContextInt64(attr string) (int64, error) {
	n, err := obj.getContextAttributeNumber(attr)
	if err == nil {
		return n.Int64()
	}
	return 0, err
}

// GetContextFloat64 returns a context attribute as an float64. It returns the
// attribute's value or an error if the attribute doesn't exist or is not a
// number.
func (obj *Object) GetContextFloat64(attr string) (float64, error) {
	n, err := obj.getContextAttributeNumber(attr)
	if err == nil {
		return n.Float64()
	}
	return 0, err
}

// GetContextString returns a context attribute as a string. It returns the
// attribute's value or an error if the attribute doesn't exist or is not a
// string.
func (obj *Object) GetContextString(attr string) (s string, err error) {
	if attrValue, attrExists := obj.data.ContextAttributes[attr]; attrExists {
		s, isString := attrValue.(string)
		if !isString {
			err = fmt.Errorf("context attribute \"%s\" is not a string", attr)
		}
		return s, err
	}
	return "", fmt.Errorf("context attribute \"%s\" does not exists", attr)
}

// GetContextBool returns a context attribute as a bool. It returns the
// attribute's value or an error if the attribute doesn't exist or is not a
// bool.
func (obj *Object) GetContextBool(attr string) (b bool, err error) {
	if attrValue, attrExists := obj.data.ContextAttributes[attr]; attrExists {
		b, isBool := attrValue.(bool)
		if !isBool {
			err = fmt.Errorf("context attribute \"%s\" is not a bool", attr)
		}
		return b, err
	}
	return false, fmt.Errorf("context attribute \"%s\" does not exists", attr)
}

// Set the value for an attribute.
func (obj *Object) Set(attr string, value interface{}) error {
	obj.modifiedAttributes = append(obj.modifiedAttributes, attr)
	obj.data.Attributes[attr] = value
	return nil
}

// SetInt64 sets the value of an integer attribute.
func (obj *Object) SetInt64(attr string, value int64) error {
	return obj.Set(attr, value)
}

// SetFloat64 sets the value of an integer attribute.
func (obj *Object) SetFloat64(attr string, value float64) error {
	return obj.Set(attr, value)
}

// SetString sets the value of a string attribute.
func (obj *Object) SetString(attr, value string) error {
	return obj.Set(attr, value)
}

// SetBool sets the value of a string attribute.
func (obj *Object) SetBool(attr string, value bool) error {
	return obj.Set(attr, value)
}

// SetTime sets the value of a time attribute.
func (obj *Object) SetTime(attr string, value time.Time) error {
	return obj.Set(attr, value.Unix())
}

// GetRelationship returns a relationship by name. Object's will have
// relationships were explicitly asked for during a call to GetObject by
// including the "relationships" paramether in the URL.
//
// Example:
//   f, _ := client.GetObject(vt.URL("files/%s?relationships=contacted_ips"))
//   // OK as "contacted_ip" was requested.
//   r, _ := f.GetRelationship("contacted_ips")
//   // Not OK, "contacted_urls" won't be present
//   r, _ := f.GetRelationship("contacted_urls")
//
func (obj *Object) GetRelationship(name string) (*Relationship, error) {
	if r, exists := obj.data.Relationships[name]; exists {
		return &Relationship{data: *r}, nil
	}
	return nil, fmt.Errorf("relationship \"%s\" doesn't exist", name)
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
