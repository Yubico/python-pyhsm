#!/bin/sh

if [ ! -d "Lib/pyhsm/" ]; then
    echo "$0: Directory Lib/pyhsm/ not found"
    exit 1
fi

if [ ! -d "doc/" ]; then
    echo "$0: Directory doc/ not found"
    exit 1
fi

test -d doc/html || mkdir doc/html/

if [ ! -d "doc/html/" ]; then
    echo "$0: Directory doc/html/ not found and could not be created"
    exit 1
fi


epydoc -n pyhsm --no-private --no-sourcecode -v -o doc/html Lib/pyhsm/
