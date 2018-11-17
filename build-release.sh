#!/usr/bin/env bash
gcc -Wall -O2 -o reunrar src/reunrar.c -lunrar -lrt -lm -lpthread "$@"
