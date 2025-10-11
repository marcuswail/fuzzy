#!/usr/bin/env bash
set -e

rm -f ../bin/vuln
cd ../src
ls
gcc -w vuln.c -o vuln   #silenzia tutti gli warning
echo "Built: vuln in /bin"

mv vuln ../bin