package syslogparser

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"regexp"
	"strconv"
	"time"

	"github.com/grafana/alloy/internal/util"
	"github.com/leodido/go-syslog/v4"
	"github.com/leodido/go-syslog/v4/nontransparent"
	"github.com/leodido/go-syslog/v4/octetcounting"
	"github.com/leodido/go-syslog/v4/rfc3164"
	"github.com/leodido/go-syslog/v4/rfc5424"
)

// ParseStream parses a rfc5424 syslog stream from the given Reader, calling
// the callback function with the parsed messages. The parser automatically
// detects octet counting.
// The function returns on EOF or unrecoverable errors.
func ParseStream(isRFC3164Message bool, useRFC3164DefaultYear bool, useFallbackParser bool, r io.Reader, callback func(res *syslog.Result), maxMessageLength int) error {
	buf := bufio.NewReaderSize(r, 1<<10)

	b, err := buf.ReadByte()
	if err != nil {
		return err
	}
	_ = buf.UnreadByte()
	cb := callback
	if isRFC3164Message && useRFC3164DefaultYear {
		cb = func(res *syslog.Result) {
			if res.Message != nil {
				rfc3164Msg := res.Message.(*rfc3164.SyslogMessage)
				if rfc3164Msg.Timestamp != nil {
					util.SetYearForLimitedTimeFormat(rfc3164Msg.Timestamp, time.Now())
				}
			}
			callback(res)
		}
	}

	// Try standard parsers first, with fallback if enabled
	if useFallbackParser {
		// Use fallback parser for better compatibility
		ParseFallbackStream(isRFC3164Message, buf, cb, maxMessageLength)
	} else {
		// Original strict parsing logic
		if b == '<' {
			if isRFC3164Message {
				nontransparent.NewParserRFC3164(syslog.WithListener(cb), syslog.WithMaxMessageLength(maxMessageLength), syslog.WithBestEffort()).Parse(buf)
			} else {
				nontransparent.NewParser(syslog.WithListener(cb), syslog.WithMaxMessageLength(maxMessageLength), syslog.WithBestEffort()).Parse(buf)
			}
		} else if b >= '0' && b <= '9' {
			if isRFC3164Message {
				octetcounting.NewParserRFC3164(syslog.WithListener(cb), syslog.WithMaxMessageLength(maxMessageLength), syslog.WithBestEffort()).Parse(buf)
			} else {
				octetcounting.NewParser(syslog.WithListener(cb), syslog.WithMaxMessageLength(maxMessageLength), syslog.WithBestEffort()).Parse(buf)
			}
		} else {
			return fmt.Errorf("invalid or unsupported framing. first byte: '%s'", string(b))
		}
	}

	return nil
}

var (
	ciscoPattern = regexp.MustCompile(`^<(\d+)>:?\s*(.*)`)
	timestampPattern = regexp.MustCompile(`^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\w{3,4}):\s*(.*)`)
	facilityPattern = regexp.MustCompile(`^(%[A-Z0-9_]+-\d+-[A-Z0-9_]+):\s*(.*)`)
	hostnamePattern = regexp.MustCompile(`:\s*(\w+)\s+%[A-Z0-9_]+-\d+-[A-Z0-9_]+:`)
	facilityNames = []string{
		"kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
		"uucp", "cron", "authpriv", "ftp", "ntp", "security", "console", "solaris-cron",
		"local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
	}
	severityNames = []string{
		"emerg", "alert", "crit", "err", "warning", "notice", "info", "debug",
	}
)

type FallbackMessage struct {
	Priority  *uint8
	Facility  *uint8
	Severity  *uint8
	Timestamp *time.Time
	Hostname  *string
	Appname   *string
	Message   *string
}

func (m *FallbackMessage) FacilityMessage() *string {
	if m.Facility == nil {
		return nil
	}
	if int(*m.Facility) < len(facilityNames) {
		s := facilityNames[*m.Facility]
		return &s
	}
	return nil
}

func (m *FallbackMessage) FacilityLevel() *string {
	return m.FacilityMessage()
}

func (m *FallbackMessage) SeverityMessage() *string {
	if m.Severity == nil {
		return nil
	}
	if int(*m.Severity) < len(severityNames) {
		s := severityNames[*m.Severity]
		return &s
	}
	return nil
}

func (m *FallbackMessage) SeverityLevel() *string {
	return m.SeverityMessage()
}

func parseFallbackMessage(line []byte) *FallbackMessage {
	msg := &FallbackMessage{}
	text := string(line)
	originalText := text
	
	// Extract priority
	priorityParsed := false
	if matches := ciscoPattern.FindStringSubmatch(text); len(matches) > 2 {
		if pri, err := strconv.Atoi(matches[1]); err == nil && pri >= 0 && pri <= 191 {
			priority := uint8(pri)
			facility := uint8(pri / 8)
			severity := uint8(pri % 8)
			msg.Priority = &priority
			msg.Facility = &facility
			msg.Severity = &severity
			text = matches[2]
			priorityParsed = true
		}
	}
	
	// Try to parse Cisco timestamp format: "Aug 13 22:08:06 UTC:"
	timestampParsed := false
	if matches := timestampPattern.FindStringSubmatch(text); len(matches) > 2 {
		if t, err := time.Parse("Jan 02 15:04:05 MST", matches[1]); err == nil {
			// Set year to current year since Cisco doesn't include it
			now := time.Now()
			t = t.AddDate(now.Year()-t.Year(), 0, 0)
			msg.Timestamp = &t
			timestampParsed = true
		}
		text = matches[2]
	}
	
	// Try to parse Cisco facility: %FACILITY-SEVERITY-MNEMONIC:
	facilityParsed := false
	if matches := facilityPattern.FindStringSubmatch(text); len(matches) > 2 {
		msg.Appname = &matches[1]
		message := matches[2]
		msg.Message = &message
		facilityParsed = true
	} else {
		// No facility found, entire text is the message
		msg.Message = &text
	}
	
	// Extract hostname if possible (look for hostname before facility code)
	if msg.Appname != nil {
		// Look for hostname pattern before the facility code in original text
		if matches := hostnamePattern.FindStringSubmatch(string(line)); len(matches) > 1 {
			msg.Hostname = &matches[1]
		}
	}
	
	// Use current time if no timestamp was parsed
	if msg.Timestamp == nil {
		now := time.Now()
		msg.Timestamp = &now
	}
	
	// Log parsing failures for debugging
	if !priorityParsed || !timestampParsed || !facilityParsed {
		log.Printf("FALLBACK_PARSE_FAILURE: priority=%v timestamp=%v facility=%v message=%q", 
			priorityParsed, timestampParsed, facilityParsed, originalText)
	}
	
	return msg
}

func ParseFallbackStream(isRFC3164Message bool, r io.Reader, callback func(res *syslog.Result), maxMessageLength int) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, maxMessageLength), maxMessageLength)
	
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		
		msg := parseFallbackMessage(line)
		
		var syslogMsg syslog.Message
		
		if isRFC3164Message {
			syslogMsg = &rfc3164.SyslogMessage{
				Base: syslog.Base{
					Priority:  msg.Priority,
					Facility:  msg.Facility,
					Severity:  msg.Severity,
					Timestamp: msg.Timestamp,
					Hostname:  msg.Hostname,
					Appname:   msg.Appname,
					Message:   msg.Message,
				},
			}
		} else {
			// Create RFC5424 message for RFC5424 mode
			syslogMsg = &rfc5424.SyslogMessage{
				Base: syslog.Base{
					Priority:  msg.Priority,
					Facility:  msg.Facility,
					Severity:  msg.Severity,
					Timestamp: msg.Timestamp,
					Hostname:  msg.Hostname,
					Appname:   msg.Appname,
					Message:   msg.Message,
				},
			}
		}
		
		callback(&syslog.Result{
			Message: syslogMsg,
			Error:   nil,
		})
	}
	
	if err := scanner.Err(); err != nil && err != io.EOF {
		callback(&syslog.Result{
			Message: nil,
			Error:   err,
		})
	}
}
