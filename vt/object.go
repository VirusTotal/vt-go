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
	"encoding/json"
	"fmt"
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

	o := object{}
	if err := json.Unmarshal(data, &o); err != nil {
		return err
	}

	obj.Type = o.Type
	obj.ID = o.ID
	obj.Attributes = o.Attributes
	obj.Relationships = o.Relationships

	for k, v := range obj.Attributes {
		if f, isFloat := v.(float64); isFloat {
			obj.Attributes[k] = int64(f)
		}
	}

	for _, v := range obj.Relationships {
		// Try unmarshalling as an array first, if it fails this is a one-to-one
		// relationship, so we should try unmarshalling a single object descriptor.
		if err := json.Unmarshal(v.Data, &v.RelatedObjects); err != nil {
			fmt.Println(err)
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
