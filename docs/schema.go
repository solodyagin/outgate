// Package schemas exposes the normative configuration schema without a runtime file dependency.
package schemas

import _ "embed"

//go:embed config.schema.json
var config string

func Config() string { return config }
