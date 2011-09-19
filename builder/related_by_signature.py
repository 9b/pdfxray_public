import pymongo
import json
from pymongo import Connection
import hash_maker

def get_data(file, collection):

        rhashes = []
        hash_look = hash_maker.get_hash_data(file, "md5")

        for md5 in collection.find({"value.hashes":hash_look},{"value.hashes":1,"_id":1}):
                rjson =  json.dumps(md5)
                ruse = json.loads(rjson)
                value = ruse.get("value")
                hashes = value.get("hashes")
                sig = ruse.get("_id")

                for hash in hashes:
                        if hash in rhashes:
				break
                        else:
                                if hash != hash_look:
                                        rhashes.append(hash)

	data = { 'hashes' : rhashes }
        return data

