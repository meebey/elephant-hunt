package main

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"regexp"
	"runtime"
	"strings"
)

// BinaryLanguageInfo holds information about the detected source language
type BinaryLanguageInfo struct {
	MostLikelyLanguage string   // Primary language guess
	Confidence         float64  // Confidence score (0-1)
	PossibleLanguages  []string // Other possible languages
	Evidence           []string // Supporting evidence
	FileType           string   // Binary format type
	Platform           string   // Target platform
}

// analyzes a binary to determine the source language
func DetectSourceLanguageFromBinary(filePath string) (BinaryLanguageInfo, error) {
	info := BinaryLanguageInfo{}
	file, err := os.Open(filePath)
	if err != nil {
		return info, err
	}
	defer file.Close()

	// First detect file type and basic info
	fileType, platform, err := detectFileType(file)
	if err != nil {
		return info, err
	}
	info.FileType = fileType
	info.Platform = platform

	// Reset file reader
	_, err = file.Seek(0, 0)
	if err != nil {
		return info, err
	}

	// Language detection based on file type
	switch fileType {
	case "PE":
		info = analyzePEFile(file, info)
	case "ELF":
		info = analyzeElfFile(file, info)
	case "Mach-O":
		fallthrough
	case "Mach-O Universal":
		info = analyzeMachOFile(file, info)
	default:
		info.MostLikelyLanguage = "Unknown"
		info.Confidence = 0
		info.Evidence = append(info.Evidence, "Unsupported binary format")
	}

	// Additional heuristics that work across formats
	info = checkForLanguageSpecificStrings(file, info)

	// Final determination
	info = determineMostLikelyLanguage(info)

	return info, nil
}

func detectFileType(file *os.File) (string, string, error) {
	// read first 8 bytes to detect file type
	magic := make([]byte, 8)
	_, err := file.Read(magic)
	if err != nil {
		return "", "", err
	}

	// Check for Mach-O universal binary first (fat binary)
	if len(magic) >= 8 {
		fatMagic := binary.BigEndian.Uint32(magic[0:4])
		if fatMagic == 0xcafebabe || fatMagic == 0xcaaebabe {
			// This is a Mach-O universal binary (fat binary)
			narch := binary.BigEndian.Uint32(magic[4:8])
			return "Mach-O Universal", fmt.Sprintf("macOS (%d architectures)", narch), nil
		}
	}

	// Check for regular Mach-O
	if len(magic) >= 4 {
		machMagic := binary.BigEndian.Uint32(magic[0:4])
		switch machMagic {
		case 0xfeedface: // MH_MAGIC
			return "Mach-O", "macOS (32-bit)", nil
		case 0xfeedfacf: // MH_MAGIC_64
			return "Mach-O", "macOS (64-bit)", nil
		case 0xcefaedfe: // MH_CIGAM
			return "Mach-O", "macOS (32-bit swapped)", nil
		case 0xcffaedfe: // MH_CIGAM_64
			return "Mach-O", "macOS (64-bit swapped)", nil
		}
	}

	// Check other file types (PE, ELF, etc.)
	switch {
	case len(magic) >= 2 && magic[0] == 0x4D && magic[1] == 0x5A: // "MZ"
		return "PE", "Windows", nil
	case len(magic) >= 4 && magic[0] == 0x7F && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F':
		return "ELF", "Unix/Linux", nil
	case len(magic) >= 4 && magic[0] == 0xCA && magic[1] == 0xFE && magic[2] == 0xBA && magic[3] == 0xBE: // Java class
		return "Java", "JVM", nil
	default:
		return "Unknown", "Unknown", nil
	}
}

func analyzePEFile(file *os.File, info BinaryLanguageInfo) BinaryLanguageInfo {
	peFile, err := pe.NewFile(file)
	if err != nil {
		info.Evidence = append(info.Evidence, "PE parsing failed: "+err.Error())
		return info
	}
	defer peFile.Close()

	// Check for .NET assemblies which indicate C#/VB/F#
	if hasDotNetMetadata(peFile) {
		info.PossibleLanguages = append(info.PossibleLanguages, "C#", "VB.NET", "F#")
		info.Evidence = append(info.Evidence, "Found .NET metadata")
	}

	// Check for Go-specific characteristics
	if isGoBinary(peFile) {
		info.PossibleLanguages = append(info.PossibleLanguages, "Go")
		info.Evidence = append(info.Evidence, "Found Go runtime indicators")
	}

	// Check for Rust characteristics
	if isRustBinary(peFile) {
		info.PossibleLanguages = append(info.PossibleLanguages, "Rust")
		info.Evidence = append(info.Evidence, "Found Rust panic strings")
	}

	// Check imported libraries
	imports := getPEImports(peFile)
	for _, i := range imports {
		switch {
		case strings.Contains(i, "go_") || i == "runtime.dll":
			info.PossibleLanguages = append(info.PossibleLanguages, "Go")
			info.Evidence = append(info.Evidence, "Go runtime: "+i)
		case strings.Contains(i, "Qt"):
			info.PossibleLanguages = append(info.PossibleLanguages, "C++")
			info.Evidence = append(info.Evidence, "Qt framework: "+i)
		case strings.Contains(i, "msvcr") || strings.Contains(i, "vcruntime"):
			info.PossibleLanguages = append(info.PossibleLanguages, "C", "C++")
			info.Evidence = append(info.Evidence, "MSVC runtime: "+i)
		}
	}

	return info
}

func analyzeElfFile(file *os.File, info BinaryLanguageInfo) BinaryLanguageInfo {
	elfFile, err := elf.NewFile(file)
	if err != nil {
		info.Evidence = append(info.Evidence, "ELF parsing failed: "+err.Error())
		return info
	}
	defer elfFile.Close()

	// Check for Go-specific sections
	if hasGoBuildInfo(elfFile) {
		info.PossibleLanguages = append(info.PossibleLanguages, "Go")
		info.Evidence = append(info.Evidence, "Found Go build info")
	}

	// Check for Rust characteristics
	if hasRustSymbols(elfFile) {
		info.PossibleLanguages = append(info.PossibleLanguages, "Rust")
		info.Evidence = append(info.Evidence, "Found Rust symbols")
	}

	// Check dynamic libraries
	libs, _ := elfFile.ImportedLibraries()
	for _, lib := range libs {
		switch {
		case strings.Contains(lib, "libgo"):
			info.PossibleLanguages = append(info.PossibleLanguages, "Go")
			info.Evidence = append(info.Evidence, "Go library: "+lib)
		case strings.Contains(lib, "libstdc++"):
			info.PossibleLanguages = append(info.PossibleLanguages, "C++")
			info.Evidence = append(info.Evidence, "C++ stdlib: "+lib)
		case strings.Contains(lib, "libgfortran"):
			info.PossibleLanguages = append(info.PossibleLanguages, "Fortran")
			info.Evidence = append(info.Evidence, "Fortran library: "+lib)
		case strings.Contains(lib, "libpython"):
			info.PossibleLanguages = append(info.PossibleLanguages, "Python")
			info.Evidence = append(info.Evidence, "Python library: "+lib)
		}
	}

	return info
}

func analyzeMachOFile(file *os.File, info BinaryLanguageInfo) BinaryLanguageInfo {
	// First check if this is a universal binary
	magic := make([]byte, 8)
	_, err := file.Read(magic)
	if err != nil {
		info.Evidence = append(info.Evidence, "Failed to read magic number: "+err.Error())
		return info
	}

	// Reset file reader
	_, err = file.Seek(0, 0)
	if err != nil {
		info.Evidence = append(info.Evidence, "Failed to seek file: "+err.Error())
		return info
	}

	var machoFile *macho.File
	if len(magic) >= 8 {
		// Handle universal binaries (fat binaries), fat binaries wrap multiple binaries
		fatMagic := binary.BigEndian.Uint32(magic[0:4])
		if fatMagic == 0xcafebabe || fatMagic == 0xcaaebabe {
			// Use fat file reader for universal binaries
			fatFile, err := macho.NewFatFile(file)
			if err != nil {
				info.Evidence = append(info.Evidence, "Failed to analyse fat Mach-O file: "+err.Error())
				return info
			}
			for _, arch := range fatFile.Arches {
				if strings.ToLower(arch.Cpu.String())[3:] == runtime.GOARCH {
					// analyse our architecture
					machoFile = arch.File
				}
			}
			if machoFile == nil && len(fatFile.Arches) > 0 {
				// if no matching arch found, take first
				machoFile = fatFile.Arches[0].File
			}
		} else {
			// Handle regular Mach-O binaries
			machoFile, err = macho.NewFile(file)
			if err != nil {
				info.Evidence = append(info.Evidence, "Failed to analyse Mach-O file: "+err.Error())
				return info
			}
		}
	} else {
		return info
	}
	defer machoFile.Close()

	// Check for Swift metadata
	if hasSwiftSections(machoFile) {
		info.PossibleLanguages = append(info.PossibleLanguages, "Swift")
		info.Evidence = append(info.Evidence, "Found Swift metadata")
	}

	// Check for Go build info
	if hasGoBuildID(machoFile) {
		info.PossibleLanguages = append(info.PossibleLanguages, "Go")
		info.Evidence = append(info.Evidence, "Found Go build ID")
	}

	// Check for Objective-C segments
	if hasObjCSections(machoFile) {
		info.PossibleLanguages = append(info.PossibleLanguages, "Objective-C")
		info.Evidence = append(info.Evidence, "Found Objective-C segments")
	}

	// Check imported libraries
	libs := getMachOImports(machoFile)
	for _, lib := range libs {
		switch {
		case strings.Contains(lib, "libswift"):
			info.PossibleLanguages = append(info.PossibleLanguages, "Swift")
			info.Evidence = append(info.Evidence, "Swift library: "+lib)
		case strings.Contains(lib, "libobjc"):
			info.PossibleLanguages = append(info.PossibleLanguages, "Objective-C")
			info.Evidence = append(info.Evidence, "Objective-C runtime: "+lib)
		case strings.Contains(lib, "libc++"):
			info.PossibleLanguages = append(info.PossibleLanguages, "C++")
			info.Evidence = append(info.Evidence, "C++ runtime: "+lib)
		}
	}

	return info
}

func checkForLanguageSpecificStrings(file *os.File, info BinaryLanguageInfo) BinaryLanguageInfo {
	// Reset file reader
	_, err := file.Seek(0, 0)
	if err != nil {
		return info
	}

	// Read first 64KB for string patterns
	data := make([]byte, 65536)
	n, _ := io.ReadFull(file, data)
	if n == 0 {
		return info
	}

	// Patterns for different languages
	patterns := map[string]*regexp.Regexp{
		"Go":     regexp.MustCompile(`runtime\.|go(itab|type|func|string|interface)`),
		"Rust":   regexp.MustCompile(`rust_panic|rust_begin_unwind|core::`),
		"C++":    regexp.MustCompile(`\.cxx_|std::|__cxa_|typeinfo for`),
		"Python": regexp.MustCompile(`PyImport_|PyEval_|Python\d\.\d`),
		"Java":   regexp.MustCompile(`java/|javax/`),
		"Node":   regexp.MustCompile(`node\.js|require\(`),
	}

	for lang, pattern := range patterns {
		if pattern.Match(data) {
			info.PossibleLanguages = append(info.PossibleLanguages, lang)
			info.Evidence = append(info.Evidence, fmt.Sprintf("Found %s patterns in binary", lang))
		}
	}

	return info
}

func determineMostLikelyLanguage(info BinaryLanguageInfo) BinaryLanguageInfo {
	if len(info.PossibleLanguages) == 0 {
		info.MostLikelyLanguage = "Unknown"
		info.Confidence = 0
		return info
	}

	// Count occurrences and assign confidence
	langCount := make(map[string]int)
	for _, lang := range info.PossibleLanguages {
		langCount[lang]++
	}

	// Find most frequent language
	maxCount := 0
	bestLang := ""
	for lang, count := range langCount {
		if count > maxCount {
			maxCount = count
			bestLang = lang
		}
	}

	info.MostLikelyLanguage = bestLang
	info.Confidence = float64(maxCount) / float64(len(info.PossibleLanguages))

	return info
}

// Helper functions for specific language detection...

func hasDotNetMetadata(f *pe.File) bool {
	// Check for .NET CLR header
	if f.OptionalHeader != nil {
		switch oh := f.OptionalHeader.(type) {
		case *pe.OptionalHeader32:
			if oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress != 0 {
				return true
			}
		case *pe.OptionalHeader64:
			if oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress != 0 {
				return true
			}
		}
	}
	return false
}

func isGoBinary(f *pe.File) bool {
	// Check for Go-specific sections or symbols
	for _, s := range f.Sections {
		if strings.Contains(s.Name, "gofunc") {
			return true
		}
		if strings.Contains(s.Name, "goinfo") {
			return true
		}
	}
	return false
}

func isRustBinary(f *pe.File) bool {
	// Check for Rust panic strings
	for _, s := range f.Sections {
		if strings.Contains(s.Name, ".rdata") {
			data, _ := s.Data()
			if bytes.Contains(data, []byte("rust_panic")) {
				return true
			}
		}
	}
	return false
}

func getPEImports(f *pe.File) []string {
	if symbols, err := f.ImportedSymbols(); err == nil {
		return symbols
	}
	return []string{}
}

func hasGoBuildInfo(f *elf.File) bool {
	// Check for Go build info section
	if sec := f.Section(".go.buildinfo"); sec != nil {
		return true
	}
	return false
}

func hasRustSymbols(f *elf.File) bool {
	syms, _ := f.Symbols()
	for _, sym := range syms {
		if strings.Contains(sym.Name, "_ZN4core") || strings.Contains(sym.Name, "_ZN3std") {
			return true
		}
	}
	return false
}

func hasSwiftSections(f *macho.File) bool {
	// Check for Swift sections
	for _, s := range f.Sections {
		if strings.Contains(s.Name, "__swift") {
			return true
		}
	}
	return false
}

func hasGoBuildID(f *macho.File) bool {
	// Check for Go build info sections
	// actual segment name examples:
	// __GNU_GO_BUILDID
	// __go_buildinfo
	for _, s := range f.Sections {
		sectionName := strings.ToLower(s.Name)
		if strings.Contains(sectionName, "_go_build") {
			return true
		}
	}
	return false
}

func hasObjCSections(f *macho.File) bool {
	// Check for Objective-C sections
	for _, s := range f.Sections {
		if strings.Contains(s.Name, "__objc") {
			return true
		}
	}
	return false
}

func getMachOImports(f *macho.File) []string {
	if libs, err := f.ImportedLibraries(); err == nil {
		return libs
	}
	return []string{}
}
