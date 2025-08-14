package syslogparser

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
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
	
	if matches := ciscoPattern.FindStringSubmatch(text); len(matches) > 2 {
		if pri, err := strconv.Atoi(matches[1]); err == nil && pri >= 0 && pri <= 191 {
			priority := uint8(pri)
			facility := uint8(pri / 8)
			severity := uint8(pri % 8)
			msg.Priority = &priority
			msg.Facility = &facility
			msg.Severity = &severity
			text = matches[2]
		}
	}
	
	parts := strings.Fields(text)
	if len(parts) > 0 {
		for i, part := range parts {
			if strings.Contains(part, "%") && strings.Contains(part, "-") {
				if i > 0 {
					hostname := strings.TrimSuffix(parts[i-1], ":")
					msg.Hostname = &hostname
				}
				
				if strings.Contains(part, ":") {
					appParts := strings.Split(part, ":")
					if len(appParts) > 0 {
						msg.Appname = &appParts[0]
					}
				} else {
					msg.Appname = &part
				}
				
				if i+1 < len(parts) {
					message := strings.Join(parts[i+1:], " ")
					msg.Message = &message
				}
				break
			}
		}
		
		if msg.Message == nil {
			fullMessage := text
			msg.Message = &fullMessage
		}
	}
	
	now := time.Now()
	msg.Timestamp = &now
	
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
