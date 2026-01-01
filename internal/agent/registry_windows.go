//go:build windows
// +build windows

package agent

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows/registry"
)

// RegistryHive represents a registry hive
type RegistryHive string

const (
	HKEY_LOCAL_MACHINE  RegistryHive = "HKLM"
	HKEY_CURRENT_USER   RegistryHive = "HKCU"
	HKEY_CLASSES_ROOT   RegistryHive = "HKCR"
	HKEY_USERS          RegistryHive = "HKU"
	HKEY_CURRENT_CONFIG RegistryHive = "HKCC"
)

var (
	ErrInvalidHive      = errors.New("invalid registry hive")
	ErrKeyNotFound      = errors.New("registry key not found")
	ErrValueNotFound    = errors.New("registry value not found")
	ErrRegAccessDenied  = errors.New("registry access denied")
	ErrInvalidValueType = errors.New("invalid value type")
)

// RegistryValue represents a registry value
type RegistryValue struct {
	Name      string `json:"name"`
	Type      string `json:"type"`
	Data      any    `json:"data"`
	DataBytes []byte `json:"data_bytes,omitempty"`
}

// RegistryKeyInfo represents registry key information
type RegistryKeyInfo struct {
	Path       string          `json:"path"`
	SubKeys    []string        `json:"sub_keys"`
	Values     []RegistryValue `json:"values"`
}

// getRegistryKey returns the registry key constant for the hive
func getRegistryKey(hive RegistryHive) (registry.Key, error) {
	switch hive {
	case HKEY_LOCAL_MACHINE:
		return registry.LOCAL_MACHINE, nil
	case HKEY_CURRENT_USER:
		return registry.CURRENT_USER, nil
	case HKEY_CLASSES_ROOT:
		return registry.CLASSES_ROOT, nil
	case HKEY_USERS:
		return registry.USERS, nil
	case HKEY_CURRENT_CONFIG:
		return registry.CURRENT_CONFIG, nil
	default:
		return 0, ErrInvalidHive
	}
}

// ReadRegistryKey reads a registry key and returns its subkeys and values
func ReadRegistryKey(hive RegistryHive, path string) (*RegistryKeyInfo, error) {
	baseKey, err := getRegistryKey(hive)
	if err != nil {
		return nil, err
	}

	key, err := registry.OpenKey(baseKey, path, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return nil, ErrKeyNotFound
		}
		return nil, fmt.Errorf("failed to open key: %w", err)
	}
	defer key.Close()

	info := &RegistryKeyInfo{
		Path:    string(hive) + "\\" + path,
		SubKeys: make([]string, 0),
		Values:  make([]RegistryValue, 0),
	}

	// Get subkeys
	subKeys, err := key.ReadSubKeyNames(-1)
	if err == nil {
		info.SubKeys = subKeys
	}

	// Get values
	valueNames, err := key.ReadValueNames(-1)
	if err == nil {
		for _, name := range valueNames {
			value, err := readRegistryValue(key, name)
			if err == nil {
				info.Values = append(info.Values, *value)
			}
		}
	}

	return info, nil
}

// ReadRegistryValue reads a single registry value
func ReadRegistryValue(hive RegistryHive, path, valueName string) (*RegistryValue, error) {
	baseKey, err := getRegistryKey(hive)
	if err != nil {
		return nil, err
	}

	key, err := registry.OpenKey(baseKey, path, registry.QUERY_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return nil, ErrKeyNotFound
		}
		return nil, fmt.Errorf("failed to open key: %w", err)
	}
	defer key.Close()

	return readRegistryValue(key, valueName)
}

func readRegistryValue(key registry.Key, name string) (*RegistryValue, error) {
	// First get the type and size
	_, valType, err := key.GetValue(name, nil)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return nil, ErrValueNotFound
		}
		return nil, fmt.Errorf("failed to get value info: %w", err)
	}

	value := &RegistryValue{
		Name: name,
	}

	switch valType {
	case registry.SZ:
		value.Type = "REG_SZ"
		s, _, err := key.GetStringValue(name)
		if err == nil {
			value.Data = s
		}

	case registry.EXPAND_SZ:
		value.Type = "REG_EXPAND_SZ"
		s, _, err := key.GetStringValue(name)
		if err == nil {
			value.Data = s
		}

	case registry.MULTI_SZ:
		value.Type = "REG_MULTI_SZ"
		ss, _, err := key.GetStringsValue(name)
		if err == nil {
			value.Data = ss
		}

	case registry.DWORD:
		value.Type = "REG_DWORD"
		v, _, err := key.GetIntegerValue(name)
		if err == nil {
			value.Data = uint32(v)
		}

	case registry.QWORD:
		value.Type = "REG_QWORD"
		v, _, err := key.GetIntegerValue(name)
		if err == nil {
			value.Data = v
		}

	case registry.BINARY:
		value.Type = "REG_BINARY"
		b, _, err := key.GetBinaryValue(name)
		if err == nil {
			value.DataBytes = b
			value.Data = fmt.Sprintf("[%d bytes]", len(b))
		}

	default:
		value.Type = fmt.Sprintf("REG_TYPE_%d", valType)
		b, _, err := key.GetBinaryValue(name)
		if err == nil {
			value.DataBytes = b
			value.Data = fmt.Sprintf("[%d bytes]", len(b))
		}
	}

	return value, nil
}

// WriteRegistryString writes a string value to the registry
func WriteRegistryString(hive RegistryHive, path, valueName, value string, expandSz bool) error {
	baseKey, err := getRegistryKey(hive)
	if err != nil {
		return err
	}

	key, _, err := registry.CreateKey(baseKey, path, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("failed to create/open key: %w", err)
	}
	defer key.Close()

	if expandSz {
		return key.SetExpandStringValue(valueName, value)
	}
	return key.SetStringValue(valueName, value)
}

// WriteRegistryMultiString writes a multi-string value to the registry
func WriteRegistryMultiString(hive RegistryHive, path, valueName string, values []string) error {
	baseKey, err := getRegistryKey(hive)
	if err != nil {
		return err
	}

	key, _, err := registry.CreateKey(baseKey, path, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("failed to create/open key: %w", err)
	}
	defer key.Close()

	return key.SetStringsValue(valueName, values)
}

// WriteRegistryDWORD writes a DWORD value to the registry
func WriteRegistryDWORD(hive RegistryHive, path, valueName string, value uint32) error {
	baseKey, err := getRegistryKey(hive)
	if err != nil {
		return err
	}

	key, _, err := registry.CreateKey(baseKey, path, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("failed to create/open key: %w", err)
	}
	defer key.Close()

	return key.SetDWordValue(valueName, value)
}

// WriteRegistryQWORD writes a QWORD value to the registry
func WriteRegistryQWORD(hive RegistryHive, path, valueName string, value uint64) error {
	baseKey, err := getRegistryKey(hive)
	if err != nil {
		return err
	}

	key, _, err := registry.CreateKey(baseKey, path, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("failed to create/open key: %w", err)
	}
	defer key.Close()

	return key.SetQWordValue(valueName, value)
}

// WriteRegistryBinary writes a binary value to the registry
func WriteRegistryBinary(hive RegistryHive, path, valueName string, data []byte) error {
	baseKey, err := getRegistryKey(hive)
	if err != nil {
		return err
	}

	key, _, err := registry.CreateKey(baseKey, path, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("failed to create/open key: %w", err)
	}
	defer key.Close()

	return key.SetBinaryValue(valueName, data)
}

// DeleteRegistryValue deletes a registry value
func DeleteRegistryValue(hive RegistryHive, path, valueName string) error {
	baseKey, err := getRegistryKey(hive)
	if err != nil {
		return err
	}

	key, err := registry.OpenKey(baseKey, path, registry.SET_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return nil // Key doesn't exist, value already deleted
		}
		return fmt.Errorf("failed to open key: %w", err)
	}
	defer key.Close()

	return key.DeleteValue(valueName)
}

// DeleteRegistryKey deletes a registry key
func DeleteRegistryKey(hive RegistryHive, path string) error {
	baseKey, err := getRegistryKey(hive)
	if err != nil {
		return err
	}

	return registry.DeleteKey(baseKey, path)
}

// CreateRegistryKey creates a registry key
func CreateRegistryKey(hive RegistryHive, path string) error {
	baseKey, err := getRegistryKey(hive)
	if err != nil {
		return err
	}

	key, _, err := registry.CreateKey(baseKey, path, registry.ALL_ACCESS)
	if err != nil {
		return fmt.Errorf("failed to create key: %w", err)
	}
	key.Close()
	return nil
}

// ListSubKeys lists subkeys of a registry key
func ListSubKeys(hive RegistryHive, path string) ([]string, error) {
	baseKey, err := getRegistryKey(hive)
	if err != nil {
		return nil, err
	}

	key, err := registry.OpenKey(baseKey, path, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return nil, ErrKeyNotFound
		}
		return nil, fmt.Errorf("failed to open key: %w", err)
	}
	defer key.Close()

	return key.ReadSubKeyNames(-1)
}
