// Command fibratus-engine evaluates rsigma-generated Fibratus filter
// expressions with Fibratus's own filter parser and evaluator.
//
// It reads a JSON request on stdin:
//
//	{"cases": [{"name": "...", "expr": "...", "events": [{"ps.exe": "...", ...}]}],
//	 "fields": ["ps.exe", ...],
//	 "macros": "/path/to/fibratus/rules/macros/macros.yml"}
//
// and writes a JSON response on stdout:
//
//	{"results": [{"name": "...", "matched": [0, 2], "error": ""}],
//	 "invalid_fields": [{"field": "...", "error": "..."}]}
//
// Macros are loaded from Fibratus's own macro library, so rule conditions
// that use them (`spawn_process`, ...) expand exactly as in the rule loader.
// Event values are converted to the Go types Fibratus's field registry
// declares for each field, the same types its event accessors produce.
package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"

	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/filter/fields"
	"github.com/rabbitstack/fibratus/pkg/filter/ql"
)

type request struct {
	Cases  []testCase `json:"cases"`
	Fields []string   `json:"fields"`
	Macros string     `json:"macros"`
}

type testCase struct {
	Name   string                   `json:"name"`
	Expr   string                   `json:"expr"`
	Events []map[string]interface{} `json:"events"`
}

type result struct {
	Name    string `json:"name"`
	Matched []int  `json:"matched"`
	Error   string `json:"error,omitempty"`
}

type invalidField struct {
	Field string `json:"field"`
	Error string `json:"error"`
}

type response struct {
	Results       []result       `json:"results"`
	InvalidFields []invalidField `json:"invalid_fields"`
}

func main() {
	var req request
	if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
		fmt.Fprintln(os.Stderr, "invalid request:", err)
		os.Exit(2)
	}
	filters := &config.Filters{Macros: config.Macros{FromPaths: []string{req.Macros}}}
	if err := filters.LoadMacros(); err != nil {
		fmt.Fprintln(os.Stderr, "cannot load macros:", err)
		os.Exit(2)
	}
	resp := response{Results: []result{}, InvalidFields: []invalidField{}}
	for _, c := range req.Cases {
		resp.Results = append(resp.Results, evalCase(c, filters))
	}
	for _, f := range req.Fields {
		if _, err := ql.NewParser(f + " = 'x'").ParseExpr(); err != nil {
			resp.InvalidFields = append(resp.InvalidFields, invalidField{f, err.Error()})
		}
	}
	if err := json.NewEncoder(os.Stdout).Encode(resp); err != nil {
		fmt.Fprintln(os.Stderr, "cannot write response:", err)
		os.Exit(2)
	}
}

func evalCase(c testCase, filters *config.Filters) result {
	r := result{Name: c.Name, Matched: []int{}}
	expr, err := ql.NewParserWithConfig(c.Expr, filters).ParseExpr()
	if err != nil {
		r.Error = "parse: " + err.Error()
		return r
	}
	for i, event := range c.Events {
		values, err := typedValues(event)
		if err != nil {
			r.Error = fmt.Sprintf("event %d: %v", i, err)
			return r
		}
		if ql.Eval(expr, values, true) {
			r.Matched = append(r.Matched, i)
		}
	}
	return r
}

func typedValues(event map[string]interface{}) (map[string]interface{}, error) {
	out := make(map[string]interface{}, len(event))
	for name, raw := range event {
		if raw == nil {
			continue
		}
		f := fields.Field(name)
		v, err := typed(f.Type(), raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		out[name] = v
	}
	return out, nil
}

func typed(t params.Type, raw interface{}) (interface{}, error) {
	switch t {
	case params.UnicodeString, params.AnsiString, params.Path:
		s, ok := raw.(string)
		if !ok {
			return nil, fmt.Errorf("want string, got %T", raw)
		}
		return s, nil
	case params.PID, params.TID, params.Uint32:
		n, ok := raw.(float64)
		if !ok {
			return nil, fmt.Errorf("want number, got %T", raw)
		}
		return uint32(n), nil
	case params.Uint16, params.Port:
		n, ok := raw.(float64)
		if !ok {
			return nil, fmt.Errorf("want number, got %T", raw)
		}
		return uint16(n), nil
	case params.Uint64:
		n, ok := raw.(float64)
		if !ok {
			return nil, fmt.Errorf("want number, got %T", raw)
		}
		return uint64(n), nil
	case params.Int64:
		n, ok := raw.(float64)
		if !ok {
			return nil, fmt.Errorf("want number, got %T", raw)
		}
		return int64(n), nil
	case params.Bool:
		b, ok := raw.(bool)
		if !ok {
			return nil, fmt.Errorf("want bool, got %T", raw)
		}
		return b, nil
	case params.IP, params.IPv4, params.IPv6:
		s, ok := raw.(string)
		if !ok {
			return nil, fmt.Errorf("want IP string, got %T", raw)
		}
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP %q", s)
		}
		return ip, nil
	default:
		return nil, fmt.Errorf("unsupported field type %v", t)
	}
}
