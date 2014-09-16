#!/bin/bash

if [ ! -f Lib/pyhsm/base.py ]; then
    echo "$0: Must be executed from top pyhsm dir."
    exit 1
fi

do_test="true"

if [ "x$1" == "x--no-test" ]; then
	do_test="false"
	shift
fi

keyid="$1"

if [ "x$keyid" = "x" ]; then
	echo "Syntax: $0 [--no-test] <KEYID>"
	exit 1
fi

set -e

version=$(grep "version\s*=" setup.py | sed "s/^.\{1,\}version\s\{0,\}=\s\{0,\}'\(.\{1,\}\)'.\{1,\}$/\1/")

sed -n -e 3p NEWS | grep -q "Version $version (released `date -I`)" || \
    (echo 'error: You need to update date/version in NEWS'; exit 1)

init_ver=$(grep __version__ Lib/pyhsm/__init__.py | awk -F \' '{print $2}')
if [ "x$init_ver" != "x$version" ]; then
    echo ""
    echo "Lib/pyhsm/__init__.py version mismatch! ($init_ver != $version) Press enter to ignore."
    read foo
fi

if git tag | grep -q "^$version\$"; then
	echo "Tag $version already exists!"
	echo "Did you remember to update the version in setup.py?"
	exit 1
fi

# update API documentation
rm -rf doc/html
./maintainer-scripts/generate_html.sh

git2cl > ChangeLog

if [ "x$do_test" != "xfalse" ]; then
	# run all unit tests
	PYTHONPATH="Lib" ./Tests/run.sh
fi

python setup.py sdist

gpg --detach-sign --default-key $keyid dist/pyhsm-$version.tar.gz
gpg --verify dist/pyhsm-$version.tar.gz.sig

git tag -s -u $keyid -m "python-pyhsm $version" $version

#Publish release
if test ! -d "$YUBICO_WWW_REPO"; then
	echo "warn: YUBICO_WWW_REPO not set or invalid!"
	echo "      This release will not be published!"
else
	$YUBICO_WWW_REPO/publish python-pyhsm $version dist/pyhsm-$version.tar.gz*
fi

echo "Done! Don't forget to git push && git push --tags"
echo ""
echo "Finished"
echo ""
ls -l dist/pyhsm-$version.tar.gz*
