__description__ = 'Builds JSON object representing a malicious PDF'
__author__ = 'Brandon Dixon'
__version__ = '1.0'
__date__ = '2011/01/01'

import pymongo
import optparse
from harness import *
from pymongo import Connection
import sys

def connect_to_mongo(host, port, database, collection):
        connection = Connection(host, port)
        db = connection[database]
        collection = db[collection]
        return collection

def main():
    oParser = optparse.OptionParser(usage='usage: %prog [options]\n' + __description__, version='%prog ' + __version__)
    oParser.add_option('-d', '--dir', default='', type='string', help='dir to build an object from')
    oParser.add_option('-m', '--mongo', action='store_true', default=False, help='dump to a mongodb database')
    (options, args) = oParser.parse_args()

    con = connect_to_mongo("localhost", 27017, "pdfs", "pdf_repo")
    
    if options.dir:
        files = []
        dirlist = os.listdir(options.dir)
        for fname in dirlist:
            if fname != "renamer.py":
                files.append(fname)
        files.sort()

        for file in files:
	    file_path = options.dir + file
            hash = file.split(".")[0]
            version_data = json.loads(snatch_version(file_path))
            con.update({"hash_data.file.md5":hash},{ "$set": { "versions":version_data } })
            print hash + " updated"

if __name__ == '__main__':
    main()
