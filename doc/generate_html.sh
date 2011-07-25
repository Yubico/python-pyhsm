#!/bin/sh

if [ ! -d "doc/html/" ]; then
    echo "$0: Directory doc/html/ not found"
    exit 1
fi

epydoc --graph all -n pyhsm --no-private --no-sourcecode -v -o doc/html Lib/pyhsm/
