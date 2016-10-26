#
# Copyright (c) 2013-2014 Yubico AB
# See the file COPYING for licence statement.
#
"""
Export AEAD from database.
"""

import os
import sys
import errno
import argparse
import sqlalchemy


import pyhsm.aead_cmd


def insert_slash(string, every=2):
    """insert_slash insert / every 2 char"""
    return os.path.join(string[i:i+every] for i in xrange(0, len(string), every))


def mkdir_p(path):
    """mkdir -p: creates path like mkdir -p"""
    try:
        os.makedirs(path)
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else: raise


def main():
    parser = argparse.ArgumentParser(description='Import AEADs into the database')

    parser.add_argument('path', help='filesystem path of where to put AEADs')
    parser.add_argument('dburl', help='connection URL for the database')
    args = parser.parse_args()


    #set the path
    path = args.path
    if not os.path.isdir(path):
        print("\nInvalid path, make sure it exists.\n")
        return 2

    #mysql url
    databaseUrl = args.dburl

    try:
        #check database connection
        engine = sqlalchemy.create_engine(databaseUrl)

        #SQLAlchemy voodoo
        metadata = sqlalchemy.MetaData()
        aeadobj = sqlalchemy.Table('aead_table', metadata, autoload=True, autoload_with=engine)
        connection = engine.connect()

    except:
        print("FATAL: Database connect failure")
        return 1

    aead = None
    nonce = None
    key_handle = None

    aead = pyhsm.aead_cmd.YHSM_GeneratedAEAD(nonce, key_handle, aead)

    #get data from the database
    result = connection.execute("SELECT * from aead_table")

    #cycle through resutls
    for row in result:
        #read values row by row
        aead.data = row['aead']
        publicId = row['public_id']
        aead.key_handle = row['keyhandle']
        aead.nonce = row['nonce']

        aead_dir = os.path.join(path, str(hex(aead.key_handle)).rstrip('L'), insert_slash(publicId))
        #sanitize path
        aead_dir = os.path.normpath(aead_dir)
        #create path
        mkdir_p(aead_dir)

        #write the file in the path
        pyhsm.aead_cmd.YHSM_GeneratedAEAD.save(aead, os.path.join(aead_dir, publicId))

    #close connection
    connection.close()


if __name__ == '__main__':
    sys.exit(main())
