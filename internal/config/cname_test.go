package config

import (
	"slices"
	"testing"
)

func TestLoad_CNAMEInspection(t *testing.T) {
	// CL 117 req 11: blocking.cname_inspection is on by default, the most private
	// value. Off, from YAML or from S_HOLE_BLOCKING_CNAME_INSPECTION, gives a
	// blocking.cname_inspection warning; on gives none.
	cases := []struct {
		name string
		yaml string
		env  map[string]string
		want bool
	}{
		{"default", "", nil, true},
		{"YAML off", "blocking:\n  cname_inspection: false\n", nil, false},
		{"YAML no", "blocking:\n  cname_inspection: no\n", nil, false},
		{"YAML on", "blocking:\n  cname_inspection: true\n", nil, true},
		{"variable off", "", map[string]string{"S_HOLE_BLOCKING_CNAME_INSPECTION": "false"}, false},
		{"variable 0", "", map[string]string{"S_HOLE_BLOCKING_CNAME_INSPECTION": "0"}, false},
		{"variable on over YAML off", "blocking:\n  cname_inspection: false\n", map[string]string{"S_HOLE_BLOCKING_CNAME_INSPECTION": "true"}, true},
		{"variable off over YAML on", "blocking:\n  cname_inspection: true\n", map[string]string{"S_HOLE_BLOCKING_CNAME_INSPECTION": "false"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, probs := mustLoadYAML(t, tc.yaml, tc.env)
			if len(probs) != 0 {
				t.Fatalf("problems = %v, want none", probs)
			}
			if cfg.Blocking.CNAMEInspection != tc.want {
				t.Errorf("CNAMEInspection = %v, want %v", cfg.Blocking.CNAMEInspection, tc.want)
			}
			warned := slices.Contains(warningKeys(cfg.Warnings()), "blocking.cname_inspection")
			if warned == tc.want {
				t.Errorf("blocking.cname_inspection warning = %v with inspection %v, want a warning only when off", warned, tc.want)
			}
		})
	}
}
