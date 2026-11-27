package servicecall

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"unicode"

	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
)

var errMountResponse = errors.New("outgate: unsafe mount response headers")

// rewriteMountResponse touches headers only. In particular it never reads Body.
func rewriteMountResponse(prefix, rawURI string, response *http.Response) error {
	normalized, err := v1.NormalizePrefix(prefix)
	path, pathErr := v1.DecodeRoutePath(rawURI)
	if err != nil || normalized != prefix || pathErr != nil || !v1.MatchesPrefix(prefix, path) {
		return errMountResponse
	}
	base, err := url.ParseRequestURI(rawURI)
	if err != nil {
		return errMountResponse
	}
	if prefix != "/" {
		// Find the escaped boundary by counting decoded bytes, without re-encoding
		// the remainder or decoding percent escapes a second time.
		escaped := base.EscapedPath()
		cut := 0
		for decoded := 0; decoded < len(prefix); decoded++ {
			if escaped[cut] == '%' {
				cut += 3
			} else {
				cut++
			}
		}
		local := escaped[cut:]
		if local == "" {
			local = "/"
		}
		base.Path, err = url.PathUnescape(local)
		if err != nil {
			return errMountResponse
		}
		base.RawPath = local
	}
	locations := response.Header.Values("Location")
	if len(locations) > 1 {
		return errMountResponse
	}
	location := ""
	if len(locations) == 1 {
		value := locations[0]
		if value == "" || len(value) > v1.MaxRawURIBytes || strings.ContainsAny(value, "\\") ||
			strings.ContainsFunc(value, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }) {
			return errMountResponse
		}
		ref, err := url.Parse(value)
		if err != nil || ref.Opaque != "" || ref.Scheme != "" && ref.Scheme != "http" && ref.Scheme != "https" ||
			(ref.Scheme != "" || strings.HasPrefix(value, "//")) && ref.Host == "" {
			return errMountResponse
		}
		decoded, err := url.PathUnescape(value)
		if err != nil || strings.ContainsFunc(decoded, unicode.IsControl) {
			return errMountResponse
		}
		location = value
		if ref.Scheme == "" && ref.Host == "" {
			local := base.ResolveReference(ref)
			// ResolveReference inherits RawQuery but not an explicitly empty
			// query marker. URL.String has no representation for an empty
			// fragment, so retain these URI delimiters separately.
			if ref.Path == "" && ref.RawQuery == "" && !ref.ForceQuery {
				local.ForceQuery = base.ForceQuery
			}
			if _, err := v1.DecodeRoutePath(local.RequestURI()); err != nil {
				return errMountResponse
			}
			if prefix != "/" {
				escaped := local.EscapedPath()
				local.Path = prefix + local.Path
				local.RawPath = (&url.URL{Path: prefix}).EscapedPath() + escaped
			}
			location = local.String()
			if strings.HasSuffix(value, "#") {
				location += "#"
			}
		}
	}
	cookies := response.Header.Values("Set-Cookie")
	rewritten := make([]string, len(cookies))
	for i, cookie := range cookies {
		rewritten[i] = rewriteCookiePath(prefix, cookie)
	}
	if len(locations) == 1 {
		response.Header.Set("Location", location)
	}
	if len(cookies) > 0 {
		response.Header["Set-Cookie"] = rewritten
	}
	return nil
}

// Preserve unknown attributes, deletion dates and individual cookie fields.
// Parsing and serializing with http.Cookie would silently discard attributes.
func rewriteCookiePath(prefix, cookie string) string {
	name, _, _ := strings.Cut(cookie, "=")
	if prefix == "/" || strings.HasPrefix(strings.TrimSpace(name), "__Host-") {
		return cookie
	}
	parts := strings.Split(cookie, ";")
	for i := 1; i < len(parts); i++ {
		name, value, ok := strings.Cut(parts[i], "=")
		path := strings.Trim(value, " \t")
		if !ok || !strings.EqualFold(strings.TrimSpace(name), "Path") || !strings.HasPrefix(path, "/") {
			continue
		}
		replacement := prefix
		if path != "/" {
			replacement += path
		}
		parts[i] = name + "=" + strings.Replace(value, path, replacement, 1)
	}
	return strings.Join(parts, ";")
}
