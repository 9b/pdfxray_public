__description__ = 'Builds JSON object representing a malicious PDF'
__author__ = 'Brandon Dixon'
__version__ = '1.0'
__date__ = '2011/01/01'

import simplejson as json
import sys
import urllib
import urllib2
import os
import time
import parser_hash2json
import parser_contents2json
import pdfid_mod
import related_entropy
import related_by_signature
import hashlib
import hash_maker
import optparse
import pymongo
import traceback
from pymongo import Connection
from pdfxray.apps.peep.harness import *

def get_vt_obj(file):
	try:
		key = 'a2fec6adeea43e021c3439fc39986b161a06d976f2a534f3cd5fb4333ce2de8f'
		url = "https://www.virustotal.com/api/get_file_report.json"
		parameters = {"resource": file, "key": key}
		data = urllib.urlencode(parameters)
		req = urllib2.Request(url, data)
		response = urllib2.urlopen(req)
		vtobj = response.read()

		preprocess = json.loads(vtobj)
		report = preprocess.get("report")
		permalink = preprocess.get("permalink")
		result = preprocess.get("result")

		if int(result) == 1:
			scanners = []
			last_scan = report[0]
			for k, v in report[1].iteritems():
				scanner = { 'antivirus' : k, 'signature' : v }
				scanners.append(scanner)

			vtobj = { 'report' : { 'last_scan':last_scan, 'permalink':permalink, 'results' : { 'scanners' : scanners } } }
		else:
			vtobj = { 'report' : { 'results': {'scanners' : [] } } }
	
	except:
		print "VT failed for " + str(file)
		vtobj = { 'report' : { 'results': {'scanners' : [] } } }

	return json.dumps(vtobj)
	
def get_structure(file):
	structureobj = pdfid_mod.PDFiD(file,True)
	return structureobj

def get_object_details(file):
	objdetails = parser_hash2json.conversion(file)
	return objdetails

def get_hash_obj(file):
	hashes = hash_maker.get_hash_object(file)
	data = { 'file': hashes }
	return json.dumps(data)	
	
def get_contents_obj(file):
	objcontents = json.loads(snatch_contents(file))
	data = { 'objects': objcontents }
	return json.dumps(data)	

def get_version_details(file):
	objcontents = json.loads(snatch_version(file))
	return json.dumps(objcontents)

#def get_related_files(file):
	#related_results = related_entropy.shot_caller(file)
	#collection = connect_to_mongo("localhost", 27017, "pdfs", "related_by_signature")
	#robj = related_by_signature.get_data(file,collection)
	#return json.dumps(robj)
	
def connect_to_mongo(host, port, database, collection):
	connection = Connection(host, port)
	db = connection[database]
	collection = db[collection]
	return collection

def build_obj(file, dir=''):

	if dir != '':
		file = dir + file

	#vt_hash = hash_maker.get_hash_data(file, "md5")
	#fhashes = json.loads(get_hash_obj(file))
	#fstructure = json.loads(get_structure(file))
	#fvt = json.loads(get_vt_obj(vt_hash))	
	#fversion = json.loads(get_version_details(file))
	#fcontents = json.loads(get_contents_obj(file))
	frelated = "null"
	
	try:
		vt_hash = hash_maker.get_hash_data(file, "md5")
	except:	
		#print str(traceback.print_exc())
		#print "VT Hash error"
		vt_hash = "error"
	
	try:
		fhashes = json.loads(get_hash_obj(file))
	except:	
		#print str(traceback.print_exc())
		#print "Hash error"
		fhashes = "error"
	
	try:
		fstructure = json.loads(get_structure(file))
	except:	
		#print str(traceback.print_exc())
		#print "Structure error"
		fstructure = "error"
	
	try:
		fvt = json.loads(get_vt_obj(vt_hash))
	except:	
		#print str(traceback.print_exc())
		#print "VT error"
		fvt = "error"
	
	try:
		fversion = json.loads(get_version_details(file))
	except:	
		#print str(traceback.print_exc())
		#print "Versions error"
		fversion = "error"
	
	try:
		fcontents = json.loads(get_contents_obj(file))
	except:	
		#print str(traceback.print_exc())
		#print "Content error"
		fail = "add"


	#build the object and then re-encode

	try:
		fobj = { "hash_data": fhashes, "structure": fstructure, "scans": { "virustotal": fvt, "wepawet": "null" }, "contents" : fcontents, 'related' : frelated, 'versions': fversion, 'tags': ['public'] }
	except:
		#print "Obj error"
		#print str(traceback.print_exc())
		fail = "fail"

	return json.dumps(fobj)
	
def main():
    oParser = optparse.OptionParser(usage='usage: %prog [options]\n' + __description__, version='%prog ' + __version__)
    oParser.add_option('-f', '--file', default='', type='string', help='file to build an object from')
    oParser.add_option('-d', '--dir', default='', type='string', help='dir to build an object from')
    oParser.add_option('-m', '--mongo', action='store_true', default=False, help='dump to a mongodb database')
    oParser.add_option('-v', '--verbose', action='store_true', default=False, help='verbose outpout')
    oParser.add_option('-a', '--auto', action='store_true', default=False, help='auto run for web portal')
    oParser.add_option('-l', '--log', action='store_true', default=False, help='log errors to file')
    (options, args) = oParser.parse_args()

    if options.log:
	log = open("error_log",'w')    

    if options.mongo:
    	con = connect_to_mongo("localhost", 27017, "pdfs", "pdf_repo")

    if options.file:
    	output = build_obj(options.file)
    	if options.mongo:
			con.insert(json.loads(output))
        if options.verbose:
			print output
    elif options.dir:
		files = []
		dirlist = os.listdir(options.dir)
		for fname in dirlist:
			files.append(fname)
		files.sort()
		count = 0

		for file in files:
			if count == 20:
				if options.verbose:
					print "Sleeping for 5 minutes"
				time.sleep(300)
				count = 0
			else:
				try:
					hash = hash_maker.get_hash_data(options.dir + file, "md5")
					pres = con.find({"hash_data.file.md5":hash}).count()
				except:
					print "Hash error"
					pres = 1
				if pres != 1:
					try:
						output = build_obj(file, options.dir)
						if options.mongo:
							try:
								con.insert(json.loads(output))
								if options.verbose:
									print file + " inserted"
							except:
								print "Something went wrong with" + file
								traceback.print_exc()
								if options.log:	
									log.write("ERROR: " + file + "\n")
						count += 1
					except:
						print "Complete build failed"
		if options.log:
			log.close()

    elif options.auto:
	while True:
	        queue = connect_to_mongo("localhost", 27017, "pdfs", "file_queue")
        	malware = connect_to_mongo("localhost",27017,"pdfs","malware")
		core = connect_to_mongo("localhost", 27017, "pdfs", "tests")
		for row in queue.find({"processed":"false"},{"hash":1,"filename":1,"_id":0}):
			row = json.dumps(row)
			ruse = json.loads(row)
			hash = ruse.get("hash")
			filename = ruse.get("filename")
                	print "proccessing " + filename
	               	path = "/var/www/mop_rest/uploads/" + filename
			hash = hash_maker.get_hash_data(path, "md5")
			pres = core.find({"hash_data.file.md5":hash}).count()
			if pres != 1:
	                	output = build_obj(path)
				try:
                			core.insert(json.loads(output))
					if options.verbose:
						print file + " inserted"
				except:
					print "Something went wrong with" + filename
					traceback.print_exc()
					if options.log:
						log.write("ERROR: " + file + "\n")

				queue.update({"hash":hash},{"$set":{"processed":"true"}})
        	        	print "processed " + filename
        	time.sleep(20)

    else:
        oParser.print_help()
        return

if __name__ == '__main__':
    main()
