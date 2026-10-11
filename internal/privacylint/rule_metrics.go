package privacylint

import (
	"go/ast"
	"go/token"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var metricLabelsRule = &Rule{
	ID: RuleMetricLabels,
	Policy: "metrics stay aggregate: no label for a client or a domain on /metrics, " +
		"and a URL goes through redact.URL (CLAUDE.md, Privacy first)",
	check: checkMetricLabels,
}

// metricLabels are the label keys that a metric line can have. A key maps to
// the function that a variable value of the label must go through. A new key
// needs a privacy review: a label for a client or a domain makes /metrics
// show each one.
var metricLabels = map[string]string{
	"upstream": "github.com/lcsabi/s-hole/internal/redact.URL",
	"url":      "github.com/lcsabi/s-hole/internal/redact.URL",
}

// printfFuncs maps a printf-style function to the index of its format
// argument.
var printfFuncs = map[string]int{
	"fmt.Fprintf": 1,
	"fmt.Sprintf": 0,
	"fmt.Printf":  0,
}

var (
	// The closing brace is optional: a literal can stop inside the label set
	// ("shole_x{client=" + c + "} 1").
	metricLabelSetRe = regexp.MustCompile(`shole_[A-Za-z0-9_]*\{([^}]*)`)
	metricLabelRe    = regexp.MustCompile(`(?:^|[,\s])([A-Za-z_][A-Za-z0-9_]*)=`)
)

// checkMetricLabels reads every string literal that holds a metric line with
// labels (shole_name{key="value"}). Each key must be in metricLabels. A value
// with a format verb must come from an argument of the printf call that the
// literal is the format of, and that argument must call the function that
// metricLabels names.
func checkMetricLabels(p *pass) {
	type use struct {
		call   *ast.CallExpr
		fmtIdx int
	}
	formats := map[*ast.BasicLit]use{}
	ast.Inspect(p.file.ast, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if idx, ok := printfFuncs[calleeName(p.info, call)]; ok && idx < len(call.Args) {
				if lit, ok := ast.Unparen(call.Args[idx]).(*ast.BasicLit); ok {
					formats[lit] = use{call, idx}
				}
			}
		}
		return true
	})
	ast.Inspect(p.file.ast, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		s, err := strconv.Unquote(lit.Value)
		if err != nil {
			return true
		}
		for _, set := range metricLabelSetRe.FindAllStringSubmatchIndex(s, -1) {
			inner := s[set[2]:set[3]]
			for _, kv := range metricLabelRe.FindAllStringSubmatchIndex(inner, -1) {
				key := inner[kv[2]:kv[3]]
				valueStart, valueEnd := labelValue(s, set[2]+kv[1], set[3])
				clean, ok := metricLabels[key]
				if !ok {
					p.report(lit, "metric label %q is not on the label allowlist (%s).", key, labelKeys())
					continue
				}
				if !strings.Contains(s[valueStart:valueEnd], "%") {
					continue // a fixed value
				}
				u, ok := formats[lit]
				if !ok {
					p.report(lit, "metric label %q gets its value from a format string that is not the format of fmt.Fprintf, fmt.Sprintf, or fmt.Printf, so the lint cannot check the value.", key)
					continue
				}
				for _, arg := range verbArgs(s, valueStart, valueEnd) {
					if arg < 0 {
						p.report(lit, "metric label %q uses an explicit argument index (%%[n]), which the lint cannot check.", key)
						continue
					}
					i := u.fmtIdx + 1 + arg
					if i >= len(u.call.Args) {
						continue // go vet reports a missing argument
					}
					if !containsCall(p.info, u.call.Args[i], clean) {
						p.report(u.call.Args[i], "the value of metric label %q does not go through %s.", key, clean[strings.LastIndex(clean, "/")+1:])
					}
				}
			}
		}
		return true
	})
}

// labelValue returns the span of the label value that starts at start and
// ends no later than end: the text inside the quotes of "value", or else the
// text up to the next comma (a value such as %q that writes its own quotes).
func labelValue(s string, start, end int) (int, int) {
	if start < end && s[start] == '"' {
		if i := strings.IndexByte(s[start+1:end], '"'); i >= 0 {
			return start + 1, start + 1 + i
		}
		return start + 1, end
	}
	if i := strings.IndexByte(s[start:end], ','); i >= 0 {
		return start, start + i
	}
	return start, end
}

// verbArgs returns the argument index of each format verb in format that
// starts in [start, end). The index is -1 for a verb with an explicit
// argument index.
func verbArgs(format string, start, end int) []int {
	var out []int
	arg := 0
	for i := 0; i < len(format); i++ {
		if format[i] != '%' {
			continue
		}
		at := i
		i++
		if i < len(format) && format[i] == '%' {
			continue
		}
		explicit := false
		for i < len(format) && strings.IndexByte("+-# 0123456789.*[]", format[i]) >= 0 {
			switch format[i] {
			case '*':
				arg++ // a width or precision from an argument
			case '[':
				explicit = true
			}
			i++
		}
		if at >= start && at < end {
			if explicit {
				out = append(out, -1)
			} else {
				out = append(out, arg)
			}
		}
		arg++
	}
	return out
}

func labelKeys() string {
	keys := make([]string, 0, len(metricLabels))
	for k := range metricLabels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ", ")
}
