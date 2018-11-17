#!/usr/bin/env bash
gcc -Wall -g -o reunrar src/reunrar.c -lunrar -lrt -lm -lpthread "$@"
