package ingest

import (
	"bytes"
	"encoding/binary"
	"path/filepath"
	"strings"
)

// Classification reports observed format hints, not a vulnerability or executed code.
// ELF e_type is intentionally not used to infer PIE versus shared-library status.
type Classification struct {
	Kind         string `json:"kind"`
	Architecture string `json:"architecture,omitempty"`
	ELFClass     string `json:"elf_class,omitempty"`
}

func classify(path string, prefix []byte) Classification {
	if len(prefix) >= 20 && bytes.Equal(prefix[:4], []byte{0x7f, 'E', 'L', 'F'}) {
		c := Classification{Kind: "elf"}
		if prefix[4] == 1 {
			c.ELFClass = "32-bit"
		} else if prefix[4] == 2 {
			c.ELFClass = "64-bit"
		}
		var machine uint16
		switch prefix[5] {
		case 1:
			machine = binary.LittleEndian.Uint16(prefix[18:20])
		case 2:
			machine = binary.BigEndian.Uint16(prefix[18:20])
		default:
			return c
		}
		switch machine {
		case 3:
			c.Architecture = "x86"
		case 8:
			c.Architecture = "mips"
		case 20:
			c.Architecture = "powerpc"
		case 40:
			c.Architecture = "arm"
		case 62:
			c.Architecture = "x86_64"
		case 183:
			c.Architecture = "aarch64"
		case 243:
			c.Architecture = "riscv"
		default:
			c.Architecture = "unknown"
		}
		return c
	}
	if bytes.HasPrefix(prefix, []byte("#!")) {
		return Classification{Kind: "script"}
	}
	name := strings.ToLower(filepath.Base(path))
	switch strings.ToLower(filepath.Ext(name)) {
	case ".sh", ".py", ".lua":
		return Classification{Kind: "script_unverified"}
	case ".js", ".css", ".html", ".htm":
		return Classification{Kind: "web_asset"}
	case ".json", ".xml", ".yaml", ".yml", ".ini", ".conf", ".cfg":
		return Classification{Kind: "configuration_candidate"}
	}
	if name == "passwd" || name == "shadow" || name == "inittab" {
		return Classification{Kind: "configuration_candidate"}
	}
	return Classification{Kind: "unknown"}
}
