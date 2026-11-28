// Package config parses and validates startup YAML without resolving secrets or opening listeners.
package config

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/dlclark/regexp2"
	"github.com/santhosh-tekuri/jsonschema/v6"
	schemas "github.com/solodyagin/outgate/docs"
	"go.yaml.in/yaml/v3"
)

var ErrConfig = errors.New("outgate: invalid deployment configuration")

const (
	MaxBytes  = 1 << 20
	maxDepth  = 64
	maxNodes  = 32768
	maxScalar = 16 << 10
)

var decimal = regexp.MustCompile(`^-?(?:0|[1-9][0-9]*)$`)

// Document is a validated, immutable input snapshot, not runtime configuration.
// It retains secret references and may contain development bearer tokens.
// String formatting is redacted; Values explicitly returns a detached sensitive copy.
// Defaults other than Mode are not materialized. Validation does not authorize startup.
type Document struct{ value map[string]any }

func (d *Document) String() string   { return "outgate deployment configuration (redacted)" }
func (d *Document) GoString() string { return d.String() }
func (d *Document) Mode() string {
	if d != nil && object(d.value, "deployment")["mode"] == "development" {
		return "development"
	}
	return "production"
}
func (d *Document) Values() map[string]any {
	if d == nil {
		return nil
	}
	return clone(d.value).(map[string]any)
}
func clone(v any) any {
	switch v := v.(type) {
	case map[string]any:
		c := make(map[string]any, len(v))
		for k, x := range v {
			c[k] = clone(x)
		}
		return c
	case []any:
		c := make([]any, len(v))
		for i, x := range v {
			c[i] = clone(x)
		}
		return c
	default:
		return v
	}
}

// Parse accepts exactly one mapping document. It performs no file, environment,
// database or network access. Input and parser errors are never included in errors.
func Parse(ctx context.Context, source []byte) (*Document, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(source) == 0 || len(source) > MaxBytes || !utf8.Valid(source) {
		return nil, ErrConfig
	}
	dec := yaml.NewDecoder(bytes.NewReader(source))
	var root, extra yaml.Node
	if err := dec.Decode(&root); err != nil || len(root.Content) != 1 {
		return nil, ErrConfig
	}
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, ErrConfig
	}
	remaining := maxNodes
	v, err := convert(ctx, root.Content[0], 0, &remaining)
	if err != nil {
		return nil, err
	}
	value, ok := v.(map[string]any)
	if !ok {
		return nil, ErrConfig
	}
	validator, err := compiled()
	if err != nil {
		return nil, ErrConfig
	}
	if err := validator.validate(ctx, value); err != nil {
		return nil, err
	}
	if err := semantics(value); err != nil {
		return nil, ErrConfig
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &Document{value: value}, nil
}

func convert(ctx context.Context, n *yaml.Node, depth int, remaining *int) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	*remaining--
	if *remaining < 0 || depth > maxDepth || len(n.Value) > maxScalar || n.Anchor != "" || n.Kind == yaml.AliasNode || n.Style&yaml.TaggedStyle != 0 && n.Tag != "!!str" {
		return nil, ErrConfig
	}
	switch n.Kind {
	case yaml.MappingNode:
		if len(n.Content) > *remaining {
			return nil, ErrConfig
		}
		result := make(map[string]any, len(n.Content)/2)
		for i := 0; i < len(n.Content); i += 2 {
			key, err := convert(ctx, n.Content[i], depth+1, remaining)
			if err != nil {
				return nil, err
			}
			s, ok := key.(string)
			if !ok || s == "<<" {
				return nil, ErrConfig
			}
			if _, exists := result[s]; exists {
				return nil, ErrConfig
			}
			v, err := convert(ctx, n.Content[i+1], depth+1, remaining)
			if err != nil {
				return nil, err
			}
			result[s] = v
		}
		return result, nil
	case yaml.SequenceNode:
		if len(n.Content) > *remaining {
			return nil, ErrConfig
		}
		result := make([]any, len(n.Content))
		for i, c := range n.Content {
			v, err := convert(ctx, c, depth+1, remaining)
			if err != nil {
				return nil, err
			}
			result[i] = v
		}
		return result, nil
	case yaml.ScalarNode:
		if n.Style != 0 {
			return n.Value, nil
		}
		switch n.Value {
		case "true":
			return true, nil
		case "false":
			return false, nil
		case "null", "":
			return nil, nil
		}
		if decimal.MatchString(n.Value) {
			return json.Number(n.Value), nil
		}
		return n.Value, nil
	default:
		return nil, ErrConfig
	}
}

type validator struct {
	mu          sync.Mutex
	schema      *jsonschema.Schema
	regexFailed bool
}
type pattern struct {
	re     *regexp2.Regexp
	failed *bool
	check  func(string) bool
}

func (p *pattern) String() string { return p.re.String() }
func (p *pattern) MatchString(s string) bool {
	ok, err := p.re.MatchString(s)
	if err != nil {
		*p.failed = true
	}
	return err == nil && ok && (p.check == nil || p.check(s))
}

type noLoader struct{}

func (noLoader) Load(string) (any, error) { return nil, ErrConfig }

var compiled = sync.OnceValues(func() (*validator, error) {
	v := &validator{}
	c := jsonschema.NewCompiler()
	c.UseLoader(noLoader{})
	c.AssertFormat()
	raw := map[string]any{}
	if err := json.Unmarshal([]byte(schemas.Config()), &raw); err != nil {
		return nil, err
	}
	defs := object(raw, "$defs")
	checks := map[string]func(string) bool{}
	add := func(name string, f func(string) bool) { checks[text(object(defs, name), "pattern", "")] = f }
	add("positiveDuration", func(s string) bool { d, err := time.ParseDuration(s); return err == nil && d > 0 })
	add("version", func(s string) bool { return len(s) <= 128 })
	add("cidr", func(s string) bool { _, err := netip.ParsePrefix(s); return err == nil })
	address := func(s string) bool {
		_, port, err := net.SplitHostPort(s)
		if err != nil {
			return false
		}
		n, err := strconv.Atoi(port)
		return err == nil && n > 0 && n <= 65535
	}
	add("listenAddress", address)
	add("loopbackAddress", address)
	c.UseRegexpEngine(func(s string) (jsonschema.Regexp, error) {
		r, err := regexp2.Compile(s, regexp2.ECMAScript)
		if err != nil {
			return nil, err
		}
		r.MatchTimeout = 50 * time.Millisecond
		return &pattern{r, &v.regexFailed, checks[s]}, nil
	})
	doc, err := jsonschema.UnmarshalJSON(bytes.NewBufferString(schemas.Config()))
	if err != nil {
		return nil, err
	}
	const id = "https://outgate.example/spec/config/config.schema.json"
	if err := c.AddResource(id, doc); err != nil {
		return nil, err
	}
	v.schema, err = c.Compile(id)
	if err != nil || v.regexFailed {
		return nil, ErrConfig
	}
	return v, nil
})

func (v *validator) validate(ctx context.Context, value any) error {
	// Serialized validation also makes any regexp timeout fail the whole document,
	// including errors inside negation/conditional schema branches.
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	v.regexFailed = false
	if err := v.schema.Validate(value); err != nil || v.regexFailed {
		return ErrConfig
	}
	return ctx.Err()
}
