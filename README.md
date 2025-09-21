Elephant Hunt
=============
[![GitHubCI pipeline status badge](https://github.com/meebey/elephant-hunt/workflows/auto-ci-builds/badge.svg)](https://github.com/meebey/elephant-hunt/commits/main) [![Go Report Card](https://goreportcard.com/badge/github.com/meebey/elephant-hunt)](https://goreportcard.com/report/github.com/meebey/elephant-hunt) ![GitHub contributors](https://img.shields.io/github/contributors-anon/meebey/elephant-hunt) [![License](https://img.shields.io/github/license/meebey/elephant-hunt.svg)](https://github.com/meebey/elephant-hunt/blob/master/LICENSE)

![GitHub Repo stars](https://img.shields.io/github/stars/meebey/elephant-hunt?style=social) [![Twitter Follow](https://img.shields.io/twitter/follow/meebey?style=social)](https://twitter.com/intent/follow?screen_name=meebey)

![GitHub Release Date](https://img.shields.io/github/release-date/meebey/elephant-hunt)

A new risk-based methodology to identify application attack-surface by analyzing the running processes, their binaries and linked libraries.

Supported features:
* quantification of attack-surface with size of executable binary and its shared libraries (excluding non-executable code)
* analyse and detect programming language

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
