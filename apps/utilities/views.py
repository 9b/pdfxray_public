from django.http import HttpResponse
from django.http import HttpResponseRedirect
from django.shortcuts import render_to_response, redirect
from django.core.urlresolvers import reverse
from django.core.context_processors import csrf
from django.views.decorators.csrf import csrf_protect
from django.template import RequestContext
from django.conf import settings
from django.core.serializers.json import DjangoJSONEncoder
from django.utils import simplejson
from pymongo import Connection
from pdfxray.apps.malpdfobj.malobjclass import *

import os
import simplejson as json
import pymongo

def connect_to_mongo(host, port, database, collection):
	connection = Connection(host, port)
	db = connection[database]
	collection = db[collection]
	return collection

def store_sample(sample):
	data = None
        try:
                con = connect_to_mongo('127.0.0.1',27017, "pdfs", "pdf_repo")
        except:
		data = None
                
        try:
                con.insert(json.loads(sample))
                data = True
        except:
                data = None
                
        return data

def get_sample(shash):
	data = None
        try:
		pub = connect_to_mongo('127.0.0.1',27017, "pdfs", "pdf_repo")
        except:
		data = None
                
        try:
		#pres = con.find({"hash_data.file.md5":shash}).count()
		#if pres == 1:
			#data = con.find_one({"hash_data.file.md5":shash},{"_id":0})
			#data = jPdf(data)
			
		pres = pub.find({"hash_data.file.md5":shash}).count()
		if pres >= 1:
			data = pub.find_one({"hash_data.file.md5":shash},{"_id":0})
			data = jPdf(data)
        except:
		data = None
                
        return data

def upsert_related_sample(fhash,data):
        try:
                con = connect_to_mongo('127.0.0.1',27017, "pdfs", "pdf_repo")
        except:
		data = None
                
        try:
		pres = con.find({"hash_data.file.md5":fhash, "related":"null"}).count()
		if pres == 1:
			data = con.update({"hash_data.file.md5":fhash},{ "$set" : data },True)
        except:
                data = None
                
        return data

def contains_related(shash):
	data = True
        try:
                con = connect_to_mongo('127.0.0.1',27017, "pdfs", "pdf_repo")
        except:
		data = None
                
        try:
		pres = con.find({"hash_data.file.md5":shash, "related":"null"}).count()
		if pres == 1:
			data = False
			return data

        except:
		data = None
                
        return data

def get_raw_sample(shash):
	data = None
        try:
                con = connect_to_mongo('127.0.0.1',27017, "pdfs", "pdf_repo")
        except:
		data = { 'error' : 'failed to connect to the database' }
                
        try:
		pres = con.find({"hash_data.file.md5":shash}).count()
		if pres == 1:
			data = con.find_one({"hash_data.file.md5":shash},{"_id":0})
			data = json.dumps(data)
			data = json.loads(data)
		else:
			return data
        except:
		return data
                
        return data

def store_file_stats(obj):
	data = None
	try:
		con = connect_to_mongo('127.0.0.1',27017, "pdfs", "file_statistics")
	except:
		data = { 'error' : 'failed to connect to the database' }
                
        try:
		con.insert(json.loads(obj))
        except:
		data = { 'error' : 'failed to query the database' }
                
        return data

def f7(seq):
	seen = set()
	seen_add = seen.add
	return [ x for x in seq if x not in seen and not seen_add(x)]

def fetch_hash_data(shash):
	data = None
	con = connect_to_mongo('127.0.0.1',27017, "pdfs", "pdf_repo")
	pres = con.find({"hash_data.file.md5":shash}).count()
	if pres == 1:
		data = con.find_one({"hash_data.file.md5":shash},{"_id":0,"hash_data.file":1})
		data = json.dumps(data)
		data = json.loads(data)
                
        return data

def fetch_structure(shash):
	data = None
	con = connect_to_mongo('127.0.0.1',27017, "pdfs", "pdf_repo")
	pres = con.find({"hash_data.file.md5":shash}).count()
	if pres == 1:
		data = con.find_one({"hash_data.file.md5":shash},{"_id":0,"structure":1})
		data = json.dumps(data)
		data = json.loads(data)
                
        return data

def fetch_scans(shash):
	data = None
	con = connect_to_mongo('127.0.0.1',27017, "pdfs", "pdf_repo")
	pres = con.find({"hash_data.file.md5":shash}).count()
	if pres == 1:
		data = con.find_one({"hash_data.file.md5":shash},{"_id":0,"scans":1})
		data = json.dumps(data)
		data = json.loads(data)
                
        return data

def fetch_contents(shash):
	data = None
	con = connect_to_mongo('127.0.0.1',27017, "pdfs", "pdf_repo")
	pres = con.find({"hash_data.file.md5":shash}).count()
	if pres == 1:
		data = con.find_one({"hash_data.file.md5":shash},{"_id":0,"contents":1})
		data = json.dumps(data)
		data = json.loads(data)
                
        return data

def fetch_raw_data(shash):
	data = None
	con = connect_to_mongo('127.0.0.1',27017, "pdfs", "pdf_repo")
	pres = con.find({"hash_data.file.md5":shash}).count()
	if pres == 1:
		data = con.find_one({"hash_data.file.md5":shash},{"_id":0})
		data = json.dumps(data)
		data = json.loads(data)
                
        return data

def search_by_sha1(sha1):
	data = None
	con = connect_to_mongo('127.0.0.1',27017, "pdfs", "pdf_repo")
	pres = con.find({"hash_data.file.sha1":sha1}).count()
	if pres == 1:
		data = con.find_one({"hash_data.file.sha1":sha1},{"_id":0,"hash_data.file":1})
		data = json.dumps(data)
		data = json.loads(data)
                
        return data

def search_by_sha256(sha256):
	data = None
	con = connect_to_mongo('127.0.0.1',27017, "pdfs", "pdf_repo")
	pres = con.find({"hash_data.file.sha256":sha256}).count()
	if pres == 1:
		data = con.find_one({"hash_data.file.sha256":sha256},{"_id":0,"hash_data.file":1})
		data = json.dumps(data)
		data = json.loads(data)
                
        return data

def search_by_raw_hash(raw_hash):
	data = None
	con = connect_to_mongo('127.0.0.1',27017, "pdfs", "pdf_repo")
	pres = con.find({"contents.objects.raw_hash":raw_hash}).count()
	if pres == 1:
		data = con.find_one({"contents.objects.raw_hash":raw_hash},{"_id":0,"hash_data.file":1})
		data = json.dumps(data)
		data = json.loads(data)
                
        return data

def search_by_encoded_hash(raw_hash):
	data = None
	con = connect_to_mongo('127.0.0.1',27017, "pdfs", "pdf_repo")
	pres = con.find({"contents.objects.stream.encoded_hash":raw_hash}).count()
	if pres == 1:
		data = con.find_one({"contents.objects.stream.encoded_hash":raw_hash},{"_id":0,"hash_data.file":1})
		data = json.dumps(data)
		data = json.loads(data)
                
        return data

def search_by_decoded_hash(raw_hash):
	data = None
	con = connect_to_mongo('127.0.0.1',27017, "pdfs", "pdf_repo")
	pres = con.find({"contents.objects.stream.decoded_hash":raw_hash}).count()
	if pres == 1:
		data = con.find_one({"contents.objects.stream.decoded_hash":raw_hash},{"_id":0,"hash_data.file":1})
		data = json.dumps(data)
		data = json.loads(data)
                
        return data

def flag_data(request):
	out = { 'results':{},'error':{},'session':{}, 'success': True }
	con = connect_to_mongo('127.0.0.1',27017, "pdfs", "pdf_repo")
	if request.user.is_authenticated:
		user = request.user.username
		flag_info = {'user':user, 'malicious': request.POST['malicious'] }
		pres = con.find({"contents.objects.stream.decoded_hash":request.POST['hash'],"contents.objects.stream.flags.user":user}).count()
		if pres != 1:
			con.update({"contents.objects.stream.decoded_hash":request.POST['hash']},{'$addToSet': { "contents.objects.$.stream.flags": flag_info } },multi=True)
		out['results'] = request.POST['hash']
		mimetype = 'application/javascript'
		data = search_by_decoded_hash(request.POST['hash'])
		if data != None:
			hash_data = data.get("hash_data")
			file = hash_data.get("file")
			md5 = file.get("md5")
			request.session[md5] = None
	
	return HttpResponse(json.dumps(out),mimetype)

def compare_detail(request):
	out = { 'results':{},'error':{},'session':{}, 'success': False }
	con = connect_to_mongo('127.0.0.1',27017, "pdfs", "pdf_repo")
	mimetype = 'application/javascript'
	upload_phash,upload_id,upload_ohash,phash,pid,pohash = request.GET['object_relation'].split("_")
	
	upload_compare = con.find_one({"hash_data.file.md5":upload_phash},{"_id":0})
	malicious_compare = con.find_one({"hash_data.file.md5":phash},{"_id":0})
	
	upload_pdf = jPdf(upload_compare)
	malicious_pdf = jPdf(malicious_compare)

	upload_obj_contents = None
	malicious_obj_contents = None

	for obj in upload_pdf.objs:
		if str(obj.id) == str(upload_id) and str(obj.raw_hash) == str(upload_ohash):
			upload_obj_contents = obj.stream_decoded_stream
			break
			
	for obj in malicious_pdf.objs:
		if str(obj.id) == str(pid) and str(obj.raw_hash) == str(pohash):
			malicious_obj_contents = obj.stream_decoded_stream
			break
		
	if upload_obj_contents != None and malicious_obj_contents != None:
		out['success'] = True
		out['uploaded_content'] = upload_obj_contents
		out['malicious_content'] = malicious_obj_contents
		
	return HttpResponse(json.dumps(out),mimetype)
