Elephant Hunt
=============
[![GitHubCI pipeline status badge](https://github.com/meebey/elephant-hunt/workflows/auto-ci-builds/badge.svg)](https://github.com/meebey/elephant-hunt/commits/main) [![Go Report Card](https://goreportcard.com/badge/github.com/meebey/elephant-hunt)](https://goreportcard.com/report/github.com/meebey/elephant-hunt) ![GitHub contributors](https://img.shields.io/github/contributors-anon/meebey/elephant-hunt) [![License](https://img.shields.io/github/license/meebey/elephant-hunt.svg)](https://github.com/meebey/elephant-hunt/blob/master/LICENSE)

![GitHub Repo stars](https://img.shields.io/github/stars/meebey/elephant-hunt?style=social) [![Twitter Follow](https://img.shields.io/twitter/follow/meebey?style=social)](https://twitter.com/intent/follow?screen_name=meebey)

![GitHub Release Date](https://img.shields.io/github/release-date/meebey/elephant-hunt)

A new risk-based methodology to identify application attack-surface by analyzing the running processes, their binaries and linked libraries.

Supported features:
* report covering all running processes
* quantification of attack-surface with size of executable binary and its shared libraries (excluding non-executable code)
* analysis and detection of programming language

Future features/ideas:
* a risk-score approach instead of raw technical numbers (e.g. bytes)
* privileged vs unprivileged user -> privileged leads to high exposure of data
* analyse and assess language safeness
* analyse open ports (needs privileged user)
* analyse and assess entry-points
  * listening TCP/UDP ports
  * Unix sockets
  * file read operations
* report with break-down per executable and size of each loaded shared library

Example Report
==============

    PID:   3608 | UID: 501 | Size: 24.7/441.7 MB | Name: Finder            | Lang: Swift       | Executable Path: /System/Library/CoreServices/Finder.app/Contents/MacOS/Finder
    PID:    867 | UID:   0 | Size: 98.8/27.9 MB  | Name: CloudflareWARP    | Lang: C++         | Executable Path: /Applications/Cloudflare WARP.app/Contents/Resources/CloudflareWARP
    PID:    959 | UID: 278 | Size: 0.3/16.9 MB   | Name: distnoted         | Lang: Objective-C | Executable Path: /usr/sbin/distnoted
    PID:  73425 | UID: 501 | Size: 2.8/5.4 MB    | Name: language-detector | Lang: Go          | Executable Path: /private/var/folders/1r/521rsgw55gs18_7rmdz13nm00000gn/T/go-build3280893093/b001/exe/language-detector
    PID:   3977 | UID: 501 | Size: 0.1/0.6 MB    | Name: dotnet            | Lang: .NET        | Executable Path: /Users/meebey/Library/Application Support/Code/User/globalStorage/ms-dotnettools.vscode-dotnet-runtime/.dotnet/8.0.20~arm64/dotnet

Required Software
=================
* GoLang

    $ apt-get install golang

Build
=====
go build main.go

Run
===
go run main.go
