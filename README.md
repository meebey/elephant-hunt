Elephant Hunt
=============
[![License](https://img.shields.io/github/license/meebey/elephant-hunt.svg)](https://github.com/meebey/elephant-hunt/blob/master/LICENSE) [![GitHubCI pipeline status badge](https://github.com/meebey/elephant-hunt/workflows/auto-ci-builds/badge.svg)](https://github.com/meebey/elephant-hunt/commits/main) ![GitHub contributors](https://img.shields.io/github/contributors-anon/meebey/elephant-hunt)

![GitHub Repo stars](https://img.shields.io/github/stars/meebey/elephant-hunt?style=social) [![Twitter Follow](https://img.shields.io/twitter/follow/meebey?style=social)](https://twitter.com/intent/follow?screen_name=meebey)

![GitHub Release Date](https://img.shields.io/github/release-date/meebey/elephant-hunt)

A new risk-based methodology to identify application attack-surface by analyzing the running processes.

Currently supported:
* quantification of attack-surface with size of executable binary and its shared libraries (excluding non-executable code)

Future:
* a risk-score approach instead of raw technical numbers (e.g. bytes)
* privileged vs unprivileged user
* analyse and assess language safeness
* analyse open ports (needs privileged user)
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
