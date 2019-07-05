#!/bin/sh

mkdir fusefs
./fs -o allow_other -o use_ino fusefs
