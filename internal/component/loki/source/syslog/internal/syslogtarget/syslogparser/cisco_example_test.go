package syslogparser

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/leodido/go-syslog/v4"
	"github.com/leodido/go-syslog/v4/rfc3164"
)

func TestCiscoExamples(t *testing.T) {
	testCases := []struct {
		name  string
		input string
	}{
		{
			name:  "Cisco with colon after priority",
			input: "<189>: 2025 Aug 13 22:08:06 UTC: %ETHPORT-5-IF_ADMIN_UP: Interface Ethernet1/2 is admin up",
		},
		{
			name:  "Cisco without priority",
			input: "1 2025-08-13T22:39:54.83Z STLSW04-N3548-L2 %DAEMON-7-SYSTEM_MSG: ntp_access_group_restrictions: no access group configured, permitting  - ntpd[27506]",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fmt.Printf("\n=== %s ===\n", tc.name)
			fmt.Printf("Input: %s\n\n", tc.input)

			var results []*syslog.Result
			callback := func(res *syslog.Result) {
				results = append(results, res)
			}

			reader := bytes.NewReader([]byte(tc.input))
			
			// Parse with fallback enabled
			err := ParseStream(true, false, true, reader, callback, 8192)
			if err != nil {
				t.Logf("Error: %v", err)
			}

			for _, res := range results {
				if res.Error != nil {
					t.Logf("Parse error: %v", res.Error)
				} else if res.Message != nil {
					if msg, ok := res.Message.(*rfc3164.SyslogMessage); ok {
						t.Log("Parsed fields:")
						
						if msg.Priority != nil {
							t.Logf("  Priority: %d", *msg.Priority)
						}
						if msg.Facility != nil {
							t.Logf("  Facility: %d (%s)", *msg.Facility, strOrNil(msg.FacilityLevel()))
						}
						if msg.Severity != nil {
							t.Logf("  Severity: %d (%s)", *msg.Severity, strOrNil(msg.SeverityLevel()))
						}
						if msg.Hostname != nil {
							t.Logf("  Hostname: %s", *msg.Hostname)
						}
						if msg.Appname != nil {
							t.Logf("  Appname: %s", *msg.Appname)
						}
						if msg.Timestamp != nil {
							t.Logf("  Timestamp: %v", *msg.Timestamp)
						}
						if msg.Message != nil {
							t.Logf("  Message: %s", *msg.Message)
						}
					}
				}
			}
		})
	}
}

func strOrNil(s *string) string {
	if s == nil {
		return "nil"
	}
	return *s
}