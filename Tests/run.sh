#!/bin/sh
#
# Run all tests.
#

mydir=`dirname $0`

set -e

: ${PYTHON:="python"}

if [ "x$1" = "x--cover" ]; then
    cd $mydir/../Lib
    exclude=""
    if [ "x$YHSM_ZAP" = "x" ]; then
	exclude="--exclude=test_configure"
    fi
    nosetests --with-coverage $exclude . ../Tests/
else
    PYTHONPATH="Lib" $PYTHON $mydir/../setup.py test $*
fi