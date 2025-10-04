package snmp

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	gosnmp "github.com/gosnmp/gosnmp"
)

const (
	oidIfName        = "1.3.6.1.2.1.31.1.1.1.1"
	oidIfDescr       = "1.3.6.1.2.1.2.2.1.2"
	oidIfOperStatus  = "1.3.6.1.2.1.2.2.1.8"
	oidIfSpeed       = "1.3.6.1.2.1.2.2.1.5"
	oidIfInErrors    = "1.3.6.1.2.1.2.2.1.14"
	oidIfOutErrors   = "1.3.6.1.2.1.2.2.1.20"
	oidIfInDiscards  = "1.3.6.1.2.1.2.2.1.13"
	oidIfOutDiscards = "1.3.6.1.2.1.2.2.1.19"
)

// InterfaceHealth represents selected SNMP counters for a single interface.
type InterfaceHealth struct {
	Index       int    `json:"index"`
	Name        string `json:"name"`
	OperStatus  string `json:"oper_status"`
	SpeedBps    uint64 `json:"speed_bps"`
	InErrors    uint64 `json:"in_errors"`
	OutErrors   uint64 `json:"out_errors"`
	InDiscards  uint64 `json:"in_discards"`
	OutDiscards uint64 `json:"out_discards"`
}

var ifOperStatusMap = map[int]string{
	1: "up",
	2: "down",
	3: "testing",
	4: "unknown",
	5: "dormant",
	6: "notPresent",
	7: "lowerLayerDown",
}

// GetInterfaceHealth fetches interface health counters for the given device and interface name.
func GetInterfaceHealth(ctx context.Context, host, community, ifaceName string) (*InterfaceHealth, error) {
	if host == "" || community == "" || ifaceName == "" {
		return nil, errors.New("host, community, and interface name are required")
	}

	g := &gosnmp.GoSNMP{
		Target:    host,
		Port:      161,
		Transport: "udp",
		Community: community,
		Version:   gosnmp.Version2c,
		Timeout:   5 * time.Second,
		Retries:   1,
		Context:   ctx,
	}

	if err := g.Connect(); err != nil {
		return nil, fmt.Errorf("snmp connect: %w", err)
	}
	defer g.Conn.Close()

	index, resolvedName, err := findInterfaceIndex(g, ifaceName)
	if err != nil {
		return nil, err
	}

	oids := []string{
		fmt.Sprintf("%s.%d", oidIfOperStatus, index),
		fmt.Sprintf("%s.%d", oidIfSpeed, index),
		fmt.Sprintf("%s.%d", oidIfInErrors, index),
		fmt.Sprintf("%s.%d", oidIfOutErrors, index),
		fmt.Sprintf("%s.%d", oidIfInDiscards, index),
		fmt.Sprintf("%s.%d", oidIfOutDiscards, index),
	}

	pkt, err := g.Get(oids)
	if err != nil {
		return nil, fmt.Errorf("snmp get: %w", err)
	}

	if len(pkt.Variables) != len(oids) {
		return nil, fmt.Errorf("unexpected SNMP response length: got %d, want %d", len(pkt.Variables), len(oids))
	}

	health := &InterfaceHealth{
		Index: index,
		Name:  resolvedName,
	}

	for i, pdu := range pkt.Variables {
		switch oids[i] {
		case fmt.Sprintf("%s.%d", oidIfOperStatus, index):
			statusVal, err := toInt(pdu)
			if err != nil {
				return nil, fmt.Errorf("parse ifOperStatus: %w", err)
			}
			health.OperStatus = ifOperStatusMap[statusVal]
			if health.OperStatus == "" {
				health.OperStatus = fmt.Sprintf("unknown(%d)", statusVal)
			}
		case fmt.Sprintf("%s.%d", oidIfSpeed, index):
			v, err := toUint64(pdu)
			if err != nil {
				return nil, fmt.Errorf("parse ifSpeed: %w", err)
			}
			health.SpeedBps = v
		case fmt.Sprintf("%s.%d", oidIfInErrors, index):
			v, err := toUint64(pdu)
			if err != nil {
				return nil, fmt.Errorf("parse ifInErrors: %w", err)
			}
			health.InErrors = v
		case fmt.Sprintf("%s.%d", oidIfOutErrors, index):
			v, err := toUint64(pdu)
			if err != nil {
				return nil, fmt.Errorf("parse ifOutErrors: %w", err)
			}
			health.OutErrors = v
		case fmt.Sprintf("%s.%d", oidIfInDiscards, index):
			v, err := toUint64(pdu)
			if err != nil {
				return nil, fmt.Errorf("parse ifInDiscards: %w", err)
			}
			health.InDiscards = v
		case fmt.Sprintf("%s.%d", oidIfOutDiscards, index):
			v, err := toUint64(pdu)
			if err != nil {
				return nil, fmt.Errorf("parse ifOutDiscards: %w", err)
			}
			health.OutDiscards = v
		}
	}

	return health, nil
}

func findInterfaceIndex(g *gosnmp.GoSNMP, ifaceName string) (int, string, error) {
	if ifaceName == "" {
		return 0, "", errors.New("interface name is required")
	}

	// Try ifName first, fall back to ifDescr if needed.
	if idx, name, err := walkForInterface(g, oidIfName, ifaceName); err == nil {
		return idx, name, nil
	}
	if idx, name, err := walkForInterface(g, oidIfDescr, ifaceName); err == nil {
		return idx, name, nil
	}
	return 0, "", fmt.Errorf("interface %q not found via SNMP", ifaceName)
}

func walkForInterface(g *gosnmp.GoSNMP, baseOID, ifaceName string) (int, string, error) {
	res, err := g.BulkWalkAll(baseOID)
	if err != nil {
		return 0, "", err
	}
	ifaceLower := strings.ToLower(ifaceName)
	for _, pdu := range res {
		name, err := toString(pdu)
		if err != nil {
			continue
		}
		if strings.EqualFold(name, ifaceName) {
			idx, err := extractIndex(baseOID, pdu.Name)
			if err != nil {
				return 0, "", err
			}
			return idx, name, nil
		}
		if strings.ToLower(name) == ifaceLower {
			idx, err := extractIndex(baseOID, pdu.Name)
			if err != nil {
				return 0, "", err
			}
			return idx, name, nil
		}
	}
	return 0, "", fmt.Errorf("interface %q not found under OID %s", ifaceName, baseOID)
}

func extractIndex(baseOID, oid string) (int, error) {
	suffix := strings.TrimPrefix(oid, baseOID+".")
	if suffix == oid {
		return 0, fmt.Errorf("unexpected oid format: %s", oid)
	}
	idx, err := strconv.Atoi(suffix)
	if err != nil {
		return 0, fmt.Errorf("invalid interface index %q: %w", suffix, err)
	}
	return idx, nil
}

func toString(pdu gosnmp.SnmpPDU) (string, error) {
	switch v := pdu.Value.(type) {
	case []byte:
		return string(v), nil
	case string:
		return v, nil
	default:
		return "", fmt.Errorf("unexpected type %T for string conversion", pdu.Value)
	}
}

func toInt(pdu gosnmp.SnmpPDU) (int, error) {
	v, err := toUint64(pdu)
	if err != nil {
		return 0, err
	}
	if v > uint64(^uint(0)>>1) {
		return 0, fmt.Errorf("value %d overflows int", v)
	}
	return int(v), nil
}

func toUint64(pdu gosnmp.SnmpPDU) (uint64, error) {
	switch v := pdu.Value.(type) {
	case uint:
		return uint64(v), nil
	case uint8:
		return uint64(v), nil
	case uint16:
		return uint64(v), nil
	case uint32:
		return uint64(v), nil
	case uint64:
		return v, nil
	case int:
		if v < 0 {
			return 0, fmt.Errorf("negative value %d", v)
		}
		return uint64(v), nil
	case int8:
		if v < 0 {
			return 0, fmt.Errorf("negative value %d", v)
		}
		return uint64(v), nil
	case int16:
		if v < 0 {
			return 0, fmt.Errorf("negative value %d", v)
		}
		return uint64(v), nil
	case int32:
		if v < 0 {
			return 0, fmt.Errorf("negative value %d", v)
		}
		return uint64(v), nil
	case int64:
		if v < 0 {
			return 0, fmt.Errorf("negative value %d", v)
		}
		return uint64(v), nil
	default:
		return 0, fmt.Errorf("unsupported type %T for integer conversion", pdu.Value)
	}
}
