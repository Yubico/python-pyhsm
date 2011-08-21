#!/bin/bash

if [ ! -f Lib/pyhsm/base.py ]; then
    echo "$0: Must be executed from top pyhsm dir."
    exit 1
fi

gitref="$1"

if [ "x$gitref" = "x" ]; then
    echo "Syntax: $0 gitref"
    exit 1
fi

tmpdir=$(mktemp -d /tmp/pyhsm_make-release.XXXXXX)
if [ ! -d "$tmpdir" ]; then
    echo "$0: Failed creating tmpdir ($tmpdir)"
    exit 1
fi


set -e

gitdesc=$(git describe $gitref)

setup_ver=$(grep version setup.py | awk -F \' '{print $2}')
if [ "x$setup_ver" != "x$gitdesc" ]; then
    echo ""
    echo "setup.py version mismatch! ($setup_ver != $gitdesc) Press enter to ignore."
    read foo
fi

init_ver=$(grep __version__ Lib/pyhsm/__init__.py | awk -F \' '{print $2}')
if [ "x$init_ver" != "x$gitdesc" ]; then
    echo ""
    echo "Lib/pyhsm/__init__.py version mismatch! ($init_ver != $gitdesc) Press enter to ignore."
    read foo
fi

releasedir="python-pyhsm-$gitdesc"
tarfile="$tmpdir/$releasedir.tar"
git archive --format=tar --prefix=${releasedir}/ ${gitref} | (cd $tmpdir && tar xf -)

# update API documentation
rm -rf doc/html
./maintainer-scripts/generate_html.sh
rsync -a --delete doc/html/ $tmpdir/$releasedir/doc/html

# update documentation from wiki
git submodule update

test -d "$tmpdir/$releasedir/doc/wiki/" && rm -rf "$tmpdir/$releasedir/doc/wiki/"
(cd doc/wiki/ && git archive --format=tar --prefix=${releasedir}/doc/wiki/ HEAD) | (cd $tmpdir && tar xf -)

echo "path : $tmpdir/$releasedir"

ls -l $tmpdir/$releasedir

# tar it up to not accidentally get junk in there while running tests etc.
(cd ${tmpdir} && tar zcf python-pyhsm-${gitdesc}.tar.gz ${releasedir})

# run all unit tests
(cd $tmpdir/$releasedir && PYTHONPATH="Lib" ./Tests/run.sh)

# sign the release
mkdir -p ../releases
cp ${tmpdir}/python-pyhsm-${gitdesc}.tar.gz ../releases
gpg --detach-sign ../releases/python-pyhsm-${gitdesc}.tar.gz
gpg --verify ../releases/python-pyhsm-${gitdesc}.tar.gz.sig

echo ""
echo "Finished"
echo ""
ls -l ../releases/python-pyhsm-${gitdesc}.tar.gz*
