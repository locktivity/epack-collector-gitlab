// Package schema embeds the JSON Schema of the collector's detailed artifact
// and its trace map. It also embeds the methods the collector gives for the
// normalized artifacts.
package schema

import (
	_ "embed"
	"encoding/json"
)

//go:embed v1.0.0.json
var detailed []byte

// methods is methods.json. For each normalized schema the collector writes,
// it holds one plain sentence on how the collector measures each field that
// is not a copy of a detailed value.
//
//go:embed methods.json
var methods []byte

// TraceMap is the map in trace-map.json, which links each field of the
// artifacts to the calls and the code behind it, for
// componentsdk.CollectorSpec.TraceMap. `make trace-map` rewrites it.
//
//go:embed trace-map.json
var TraceMap []byte

// Schemas maps each artifact path to its JSON Schema, for
// componentsdk.CollectorSpec.Schemas. The normalized artifacts are checked
// against the SDK's own schemas for their types.
func Schemas() map[string][]byte {
	return map[string][]byte{"artifacts/gitlab.details.json": detailed}
}

// Methods returns the sentences in methods.json for
// componentsdk.CollectorSpec.Methods, keyed by schema ID and then by field.
// Each one becomes the x-epack-method of its field in the SDK's schema for
// that type.
func Methods() map[string]map[string]string {
	var bySchema map[string]map[string]string
	if err := json.Unmarshal(methods, &bySchema); err != nil {
		panic("docs/schema/methods.json: " + err.Error())
	}
	return bySchema
}
