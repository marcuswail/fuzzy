#!/usr/bin/env bash
set -e

rm -f ./vuln1
gcc -w vuln.c -o vuln1   #silenzia tutti gli warning
echo "Built: vuln1"

