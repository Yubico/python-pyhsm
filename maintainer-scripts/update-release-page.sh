#!/bin/sh

set -e

version="$1"

if [ "x$version" = "x" ]; then
    echo "Syntax: $0 version"
    exit 1
fi

release_dir="../releases/"
release_tar="python-pyhsm-${version}.tar.gz"
release_sig="${release_tar}.sig"

if [ ! -f "${release_dir}${release_tar}" ]; then
    echo "$0: ${release_dir}${release_tar} not found"
    exit 1
fi

if [ ! -f "${release_dir}${release_sig}" ]; then
    echo "$0: ${release_dir}${release_sig} not found"
    exit 1
fi

#Update releases page
git checkout gh-pages
cp ${release_dir}${release_tar} releases/
cp ${release_dir}${release_sig} releases/
git add releases/${release_tar}
git add releases/${release_sig}

versions=$(ls -1v releases/python-pyhsm-*.tar.gz | awk -F\- '{print $3}' | sed 's/.tar.gz//' | paste -sd ',' - | sed 's/,/, /g' | sed 's/\([0-9.a-z]\{1,\}\)/"\1"/g')
sed -i -e "2s/\[.*\]/[${versions}]/" releases.html
git add releases.html
git commit -m "Added release ${version}."
git push
git checkout master

echo "Success!"
