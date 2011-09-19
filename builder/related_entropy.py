import math
import json
import os
import difflib
import pymongo
from pymongo import Connection

def connect_to_mongo(host, port, database, collection):
        connection = Connection(host, port)
        db = connection[database]
        collection = db[collection]
        return collection

def generate_related(sample):
        objects = []
        collection = connect_to_mongo("127.0.0.1", 27017, "pdfs", "obj_cutdown")
        for obj in sample.objs:
                matches = []
                ds1 = obj.derived_string
                length = len(obj.derived_string)
                if length > 4:
                        for m in collection.find({"dlength":length},{"_id":0}):
                                dirty = json.dumps(m)
                                clean = json.loads(dirty)
                                obj_hash = clean.get("hash")
                                ds2 = clean.get("dstring")
                                parent = clean.get("parent")
                                id = clean.get("id")
                                sus = clean.get("suspicious")
                                s = difflib.SequenceMatcher(None, ds1,ds2)
                                if s.ratio() > .95 and sus != "":
                                        match = { 'parent_file_hash': parent, 'mobj_hash': obj_hash, 'mobj_id': id }
                                        matches.append(match)
                                        
                        if len(matches) > 0:
                                construct = { 'sobj_hash':obj.hash, 'sobj_id':obj.id, 'matches': matches }
                                objects.append(construct)

        total = { 'related': { "objects": objects } }
        total = json.dumps(total)
        return json.loads(total)
