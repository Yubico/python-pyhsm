#
# Copyright (c) 2013-2014 Yubico AB
# See the file COPYING for licence statement.
#
"""
Import AEADs to database.
"""

import os
import re
import sys
import argparse
import sqlalchemy

from pyhsm.util import key_handle_to_int
import pyhsm.aead_cmd


def extract_keyhandle(path, filepath):
    """extract keyhandle value from the path"""

    keyhandle = filepath.lstrip(path)
    keyhandle = keyhandle.split("/")
    return keyhandle[0]


def insert_query(connection, publicId, aead, keyhandle, aeadobj):
    """this functions read the response fields and creates sql query. then
    inserts everything inside the database"""

    # turn the keyhandle into an integer
    keyhandle = key_handle_to_int(keyhandle)
    if not keyhandle == aead.key_handle:
        print("WARNING: keyhandle does not match aead.key_handle")
        return None

    # creates the query object
    try:
        sql = aeadobj.insert().values(public_id=publicId, keyhandle=aead.key_handle, nonce=aead.nonce, aead=aead.data)
        # insert the query
        result = connection.execute(sql)
        return result
    except sqlalchemy.exc.IntegrityError:
        pass
    return None


def main():
    parser = argparse.ArgumentParser(description='Import AEADs into the database')

    parser.add_argument('path', help='filesystem path of where to find AEADs')
    parser.add_argument('dburl', help='connection URL for the database')

    args = parser.parse_args()

    path = args.path
    databaseUrl = args.dburl

    if not os.path.isdir(path):
        print("\nInvalid path, check your spelling.\n")
        return 2

    try:
        engine = sqlalchemy.create_engine(databaseUrl)

        #SQLAlchemy voodoo
        metadata = sqlalchemy.MetaData()
        aeadobj = sqlalchemy.Table('aead_table', metadata, autoload=True, autoload_with=engine)
        connection = engine.connect()
    except:
        print("FATAL: Database connect failure")
        return 1

    for root, subFolders, files in os.walk(path):
        if files:
            if not re.match(r'^[cbdefghijklnrtuv]+$', files[0]):
                continue

            #build file path
            filepath = os.path.join(root, files[0])

            #extract the key handle from the path
            keyhandle = extract_keyhandle(path, filepath)
            kh_int = pyhsm.util.key_handle_to_int(keyhandle)

            #instantiate a new aead object
            aead = pyhsm.aead_cmd.YHSM_GeneratedAEAD(None, kh_int, '')
            aead.load(filepath)

            #set the public_id
            public_id = str(files[0])

            #check it is old format aead
            if not aead.nonce:
                #configure values for oldformat
                aead.nonce = pyhsm.yubikey.modhex_decode(public_id).decode('hex')
                aead.key_handle = key_handle_to_int(keyhandle)

            if not insert_query(connection, public_id, aead, keyhandle, aeadobj):
                print("WARNING: could not insert %s" % public_id)

    #close sqlalchemy
    connection.close()


if __name__ == '__main__':
    sys.exit(main())
