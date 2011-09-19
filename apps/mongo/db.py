import pymongo
import traceback
from pymongo import Connection

class mongo():
	def __init__(self,host,port,database,collection):
		con = self.connect_to_mongo(host, port, database, collection)

	def connect_to_mongo(self,host, port, database, collection):
		connection = Connection(host, port)
		db = connection[database]
		collection = db[collection]
		return collection
