#!/bin/sh

cc -o protectfile protectfile.c aes.c
cc -o setkey setkey.c
cc -o fs fs.c aes.c `pkgconf fuse --cflags --libs`