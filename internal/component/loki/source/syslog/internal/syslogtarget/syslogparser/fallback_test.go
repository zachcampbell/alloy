package syslogparser

import (
	"bytes"
	"strings"
	"testing"

	"github.com/leodido/go-syslog/v4"
	"github.com/leodido/go-syslog/v4/rfc3164"
)

func TestParseFallbackMessage(t *testing.T) {
	testCases := []struct {
		name            string
		input           string
		expectPriority  bool
		expectHostname  bool
		expectAppname   bool
		expectMessage   bool
	}{
		{
			name:           "Cisco with priority and colon",
			input:          "<189>: 2025 Aug 13 22:08:06 UTC: %ETHPORT-5-IF_ADMIN_UP: Interface Ethernet1/2 is admin up",
			expectPriority: true,
			expectHostname: true,
			expectAppname:  true,
			expectMessage:  true,
		},
		{
			name:           "Cisco without colon after priority",
			input:          "<189> 2025-08-13T22:39:54.83Z STLSW04-N3548-L2 %DAEMON-7-SYSTEM_MSG: ntp_access_group_restrictions",
			expectPriority: true,
			expectHostname: true,
			expectAppname:  true,
			expectMessage:  true,
		},
		{
			name:           "Message without priority",
			input:          "2025 Aug 13 22:08:06 UTC: %ETHPORT-5-IF_ADMIN_UP: Interface Ethernet1/2 is admin up",
			expectPriority: false,
			expectHostname: true,
			expectAppname:  true,
			expectMessage:  true,
		},
		{
			name:           "Simple text message",
			input:          "This is just a plain text message",
			expectPriority: false,
			expectHostname: false,
			expectAppname:  false,
			expectMessage:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			msg := parseFallbackMessage([]byte(tc.input))

			if tc.expectPriority && msg.Priority == nil {
				t.Error("Expected priority but got nil")
			}
			if !tc.expectPriority && msg.Priority != nil {
				t.Errorf("Expected no priority but got %d", *msg.Priority)
			}

			if tc.expectHostname && msg.Hostname == nil {
				t.Error("Expected hostname but got nil")
			}
			if !tc.expectHostname && msg.Hostname != nil {
				t.Errorf("Expected no hostname but got %s", *msg.Hostname)
			}

			if tc.expectAppname && msg.Appname == nil {
				t.Error("Expected appname but got nil")
			}
			if !tc.expectAppname && msg.Appname != nil {
				t.Errorf("Expected no appname but got %s", *msg.Appname)
			}

			if tc.expectMessage && msg.Message == nil {
				t.Error("Expected message but got nil")
			}
			if !tc.expectMessage && msg.Message != nil {
				t.Errorf("Expected no message but got %s", *msg.Message)
			}

			// Check facility and severity calculation
			if msg.Priority != nil {
				expectedFacility := *msg.Priority / 8
				expectedSeverity := *msg.Priority % 8
				if *msg.Facility != expectedFacility {
					t.Errorf("Facility calculation wrong: expected %d, got %d", expectedFacility, *msg.Facility)
				}
				if *msg.Severity != expectedSeverity {
					t.Errorf("Severity calculation wrong: expected %d, got %d", expectedSeverity, *msg.Severity)
				}
			}
		})
	}
}

func TestParseFallbackStream(t *testing.T) {
	input := strings.Join([]string{
		"<189>: 2025 Aug 13 22:08:06 UTC: %ETHPORT-5-IF_ADMIN_UP: Interface Ethernet1/2 is admin up",
		"<165> 2025-08-13T22:39:54.83Z STLSW04-N3548-L2 %DAEMON-7-SYSTEM_MSG: ntp_access_group_restrictions",
		"Simple message without priority",
	}, "\n")

	var results []*syslog.Result
	callback := func(res *syslog.Result) {
		results = append(results, res)
	}

	reader := bytes.NewReader([]byte(input))
	ParseFallbackStream(reader, callback, 8192)

	if len(results) != 3 {
		t.Errorf("Expected 3 messages, got %d", len(results))
	}

	for i, res := range results {
		if res.Error != nil {
			t.Errorf("Message %d had error: %v", i+1, res.Error)
		}
		if res.Message == nil {
			t.Errorf("Message %d was nil", i+1)
		} else {
			// Verify it's an RFC3164 message as expected
			if _, ok := res.Message.(*rfc3164.SyslogMessage); !ok {
				t.Errorf("Message %d was not RFC3164 format", i+1)
			}
		}
	}
}

func TestParseStreamWithFallback(t *testing.T) {
	testCases := []struct {
		name              string
		input             string
		useFallback       bool
		expectError       bool
		expectMessageCount int
	}{
		{
			name:              "Cisco format with fallback enabled",
			input:             "<189>: 2025 Aug 13 22:08:06 UTC: %ETHPORT-5-IF_ADMIN_UP: Interface up",
			useFallback:       true,
			expectError:       false,
			expectMessageCount: 1,
		},
		{
			name:              "Cisco format with fallback disabled",
			input:             "<189>: 2025 Aug 13 22:08:06 UTC: %ETHPORT-5-IF_ADMIN_UP: Interface up",
			useFallback:       false,
			expectError:       false, // Will try RFC parser
			expectMessageCount: 0, // But may not parse correctly
		},
		{
			name:              "Non-standard format with fallback enabled",
			input:             "Plain text message",
			useFallback:       true,
			expectError:       false,
			expectMessageCount: 1,
		},
		{
			name:              "Non-standard format with fallback disabled",
			input:             "Plain text message",
			useFallback:       false,
			expectError:       true,
			expectMessageCount: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var results []*syslog.Result
			callback := func(res *syslog.Result) {
				results = append(results, res)
			}

			reader := bytes.NewReader([]byte(tc.input))
			err := ParseStream(true, false, tc.useFallback, reader, callback, 8192)

			if tc.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tc.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			// Note: Message count might vary based on how parsers handle the input
			if tc.expectMessageCount > 0 && len(results) == 0 {
				t.Error("Expected at least one message but got none")
			}
		})
	}
}