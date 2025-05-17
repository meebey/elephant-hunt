package main

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"

	"code.cloudfoundry.org/bytefmt"         // to convert bytes into/from human-readable format
	. "github.com/ahmetb/go-linq"           // LINQ for Go to manage data structure like its 2025
	"github.com/shirou/gopsutil/v4/process" // to get process information
)

var (
	gLibraryNameRegex *regexp.Regexp
)

type ProcessInfo struct {
	pid                      int32
	name                     string
	user_id                  int
	executable_path          string
	executable_size_in_bytes int64
	libraries_size_in_bytes  int64
}

func main() {
	fmt.Println("Let's hunt for the elephant in the room...")

	// get a list of all running processes
	processes, err := process.Processes()
	if err != nil {
		fmt.Printf("Error getting processes: %v\n", err)
		return
	}
	fmt.Printf("Analysing %d running processes...\n", len(processes))

	// analyse each process
	processInfos := []ProcessInfo{}
	for _, proc := range processes {
		procInfo := ProcessInfo{pid: proc.Pid}
		procInfo.name, _ = proc.Name()
		procInfo.executable_path, _ = proc.Exe()
		user_ids, _ := proc.Uids()
		if len(user_ids) > 0 {
			procInfo.user_id = int(user_ids[0])
		}

		if procInfo.executable_path == "" {
			// ignore internal processes
			fmt.Printf("WARNING: process with pid: %d has no executable_path\n", procInfo.pid)
			continue
		}

		// don't analyse same binary running as same user again (a priv process still has higher risk)
		isProcessedAlreadyAnalysed := From(processInfos).CountWithT(
			func(p ProcessInfo) bool {
				return p.executable_path == procInfo.executable_path &&
					p.user_id == procInfo.user_id
			}) > 0
		if isProcessedAlreadyAnalysed {
			continue
		}

		fileInfo, err := os.Stat(procInfo.executable_path)
		if err == nil {
			procInfo.executable_size_in_bytes = fileInfo.Size()
		}

		fmt.Printf("analysing executable: %s...\n", procInfo.executable_path)

		// analyze dynamically linked and loaded libraries into memory that increase the attack-surface
		procInfo.libraries_size_in_bytes = 0
		libraries, err := getDynamicLibraries(procInfo.executable_path)
		if err != nil {
			fmt.Printf("warning: could not get libraries: %s\n", err)
			continue
		}
		for _, library := range libraries {
			//fmt.Printf("library: %s\n", library)
			librarySize, err := getDynamicLibrarySize(library)
			if err != nil {
				fmt.Printf("warning: %v\n", err)
				continue
			}
			procInfo.libraries_size_in_bytes += librarySize
		}

		// TODO: analyse dynamically dlopen()ed libraries, with lsof -p $PID perhaps?

		// TODO: analyse listening UDP/TCP ports
		// lsof -i4 -i6 -nP

		// TODO: detect memory-(un)safe languages an bump risk score
		// otool -L path_to_app | grep libc++.1.dylib -> C++
		// nm -g /nix/store/dq249g0b6iqjh3xfjc08gqy2h1590x44-alacritty-0.13.2/bin/alacritty | grep rust_panic -> rust
		// otool -L path_to_app| grep libswiftCore.dylib -> Swift
		// nm -g path_to_app | grep swift_stdlib -> Swift

		processInfos = append(processInfos, procInfo)
	}

	// use LINQ to sort the list by size
	var sortedProcessInfos []ProcessInfo
	From(processInfos).
		OrderByDescendingT(func(p ProcessInfo) int {
			return int(p.executable_size_in_bytes + p.libraries_size_in_bytes)
		}).
		ToSlice(&sortedProcessInfos)

	// TODO: calculate a risk exposure score
	// TODO: executable running as uid 0 has higher risk score

	// TODO: remove duplicate executables running as the same user, as these don't increase the attack-surface.
	// same executable running as different users do increase the exposure though as more data is at risk.

	for _, info := range sortedProcessInfos {
		var displayedName string
		if info.name == "" {
			displayedName = "N/A"
		} else {
			displayedName = info.name
		}

		fmt.Printf("PID: %6d | UID: %3d | Size: %3.1f/%3.1f MB | Name: %s | Executable Path: %s \n",
			info.pid, info.user_id,
			float64(info.executable_size_in_bytes)/1024/1024,
			float64(info.libraries_size_in_bytes)/1024/1024,
			displayedName, info.executable_path)
	}
}

// retrieves the list of dynamically loaded libraries for an executable
func getDynamicLibraries(exePath string) ([]string, error) {
	if exePath == "" {
		return nil, fmt.Errorf("no executable path provided")
	}

	// Use `ldd` on Linux or `otool -L` on macOS
	os := runtime.GOOS
	var cmd *exec.Cmd
	switch os {
	case "linux":
		cmd = exec.Command("ldd", exePath)
	case "darwin":
		cmd = exec.Command("otool", "-L", exePath)
	default:
		return nil, fmt.Errorf("unsupported OS: %s", os)
	}

	// Run the command and capture the output
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve libraries: %v", err)
	}

	// Parse the output
	lines := strings.Split(string(output), "\n")
	var libraries []string
	if gLibraryNameRegex == nil {
		// initialize static regex instance
		// use regex to match and remove the compatibility information in parentheses that Darwin's otool outputs, e.g.
		// /usr/lib/libobjc.A.dylib (compatibility version 1.0.0, current version 228.0.0)
		gLibraryNameRegex = regexp.MustCompile(`\s*\([^)]*\)`)
	}
	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if trimmedLine == "" {
			continue
		}
		var libraryPath string
		if os == "darwin" {
			strippedLine := gLibraryNameRegex.ReplaceAllString(trimmedLine, "")
			// omit the path of the executable that otool outputs, this is not a library
			if strings.HasSuffix(strippedLine, ":") {
				continue
			}
			libraryPath = strippedLine
		} else {
			libraryPath = trimmedLine
		}
		libraries = append(libraries, libraryPath)
	}

	return libraries, nil
}

func getDynamicLibrarySize(libraryPath string) (int64, error) {
	runningOs := runtime.GOOS
	switch runningOs {
	case "darwin":
		// on darwin (macOS) as of macOS Catalina (10.15) core system libraries are no longer placed in /usr/lib/ and not regular files either
		// to get their information, we use dyld_info which works boths for core system libraries and framework paths
		// e.g. these commands work and provide their information:
		// dyld_info /usr/lib/libSystem.B.dylib
		// dyld_info /System/Library/Frameworks/IOKit.framework/Versions/A/IOKit

		// handle special library paths
		switch libraryPath {
		case "/System/DriverKit/usr/lib/libc++.dylib":
			libraryPath = "/usr/lib/libc++.dylib"
		case "/System/DriverKit/System/Library/Frameworks/DriverKit.framework/DriverKit":
			libraryPath = "/System/Library/Frameworks/DriverKit.framework/DriverKit"
		case "/System/DriverKit/System/Library/Frameworks/SerialDriverKit.framework/SerialDriverKit":
			libraryPath = "/System/Library/Frameworks/SerialDriverKit.framework/SerialDriverKit"
		case "/usr/appleinternal/lib/liblinkguard.dylib":
			return 0, nil
		}

		if strings.HasPrefix(libraryPath, "/AppleInternal/Library/Frameworks/") {
			// these frameworks can't be queried with dyld_info
			return 0, nil
		}

		if strings.HasPrefix(libraryPath, "@rpath/") {
			// TODO: support looking up @rpath
			return 0, nil
		}

		if strings.HasPrefix(libraryPath, "@executable_path/") {
			// TODO: support looking up @executable_path
			return 0, nil
		}

		// get code/text segment size of library which contains the executable instructions
		// note: we deliberately ignore the data and other sections as they are static artifacts
		// and are not at risk of being penetrated
		// TODO: parse dynamically linked libraries and recurse into them
		shellCommand := fmt.Sprintf("dyld_info -segments '%s' | grep __TEXT | awk '{print $3}' | head -n 1", libraryPath)
		var cmd *exec.Cmd
		cmd = exec.Command("sh", "-c", shellCommand)
		output, err := cmd.Output()
		if err != nil {
			return 0, fmt.Errorf("failed to retrieve library information for %s, error: %v", libraryPath, err)
		}
		if len(output) == 0 {
			//fmt.Printf("WARNING: library: '%s' has no __TEXT section?!\n", libraryPath)
			return 0, nil
		}
		bytes, err := bytefmt.ToBytes(string(output))
		if err != nil {
			return 0, fmt.Errorf("failed to convert string '%s' to bytes, error: %v", output, err)
		}
		return int64(bytes), nil
	case "linux":
		_, err2 := os.Readlink(libraryPath)
		if err2 != nil {
			return 0, fmt.Errorf("%s is a symbolic link", libraryPath)
		} else {
			// on Linux we can simply stat the library path as they are regular files
			fileInfo, err := os.Stat(libraryPath)
			if err != nil {
				return 0, err
			}
			return fileInfo.Size(), nil
		}
	default:
		return 0, fmt.Errorf("unsupported OS: %s", runningOs)
	}
}
