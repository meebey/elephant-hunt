package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"regexp"
	. "github.com/ahmetb/go-linq"
	"github.com/shirou/gopsutil/v4/process"
)

type ProcessInfo struct {
	pid int32
	name string
	user_id int
	executable_path string
	executable_size_in_bytes int64
	libraries_size_in_bytes int64
}

func main() {
	fmt.Println("Let's hunt for the elephant in the room...")

	// get a list of all running processes
	processes, err := process.Processes()
	if err != nil {
		fmt.Printf("Error getting processes: %v\n", err)
		return
	}

	// analyse each process
	processInfos := []ProcessInfo{}
	for _, proc := range processes {
		procInfo := ProcessInfo{pid: proc.Pid}
		procInfo.name, _ = proc.Name()
		procInfo.executable_path, _ = proc.Exe()
		user_ids, _ := proc.Uids()
		if (len(user_ids) > 0) {
			procInfo.user_id = int(user_ids[0])
		}

		if procInfo.executable_path != "" {
			fileInfo, err := os.Stat(procInfo.executable_path)
			if err == nil {
				procInfo.executable_size_in_bytes = fileInfo.Size()
			}

			//fmt.Printf("executable: %s\n", procInfo.executable_path)

			// analyze dynamically linked and loaded libraries into memory that increase the attack-surface
			procInfo.libraries_size_in_bytes = 0
			libraries, err := getDynamicLibraries(procInfo.executable_path)
			if err != nil {
				fmt.Println("warning: could not get libraries: %s", err)
				continue
			}
			for _, library := range libraries {
				//fmt.Printf("library: %s\n", library)
				fileInfo, err := os.Stat(library)
				if err != nil {
					//fmt.Println("warning: could not get file size for library: %s, error: %s", library, err)
					continue
				}
				procInfo.libraries_size_in_bytes += fileInfo.Size()
			}
		}

		// TODO: analyse dynamically dlopen()ed libraries, with lsof -p $PID perhaps?

		// TODO: analyse listening UDP/TCP ports

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
			return int(p.executable_size_in_bytes)
		}).
		ToSlice(&sortedProcessInfos)

	// TODO: calculate a risk exposure score
	// TODO: executable running as uid 0 has higher risk score

	// TODO: remove duplicate executables running as the same user, as these don't increase the attack-surface.
	// same executable running as different users do increase the exposure though as more data is at risk.

	for _, info := range sortedProcessInfos {
		fmt.Printf("PID: %6d | UID: %3d | Size: %2.1f/%2.1f MB | Name: %s | Executable Path: %s \n",
					info.pid, info.user_id,
					float64(info.executable_size_in_bytes) / 1024 / 1024,
					float64(info.libraries_size_in_bytes) / 1024 / 1024,
					info.name, info.executable_path)
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
	// use regex to match and remove the compatibility information in parentheses that Darwin's otool outputs, e.g.
	// /usr/lib/libobjc.A.dylib (compatibility version 1.0.0, current version 228.0.0)
	re := regexp.MustCompile(`\s*\([^)]*\)`)
	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if trimmedLine == "" {
			continue
		}
		var strippedLine string
		if os == "darwin" {
			strippedLine = re.ReplaceAllString(trimmedLine, "")
			// omit the path of the executable that otool outputs, this is not a library
			if strings.HasSuffix(strippedLine, ":") {
				continue
			}
			// FIXME: handle otool not returning paths to actual shared libraries but framework directories
			// where/how are the .dylib files loaded on macOS?
		} else {
			strippedLine = trimmedLine
		}
		libraries = append(libraries, strippedLine)
	}

	return libraries, nil
}