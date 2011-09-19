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
from pdfxray.apps.utilities.views import connect_to_mongo

import os
import simplejson as json
import pymongo
from time import time

@csrf_protect
def get_status(request):
	hold = []
	out = { 'results':{},'error':{},'session':{} }
	con = connect_to_mongo('127.0.0.1',27017, "pdfs", "pdf_repo")
	data = con.find_one({"hash_data.file.md5":request.POST['hash']},{'tags':1,'_id':0})
	if data != None:
		data = json.dumps(data)
		data = json.loads(data)
		tags = data.get("tags")
		all_tags = ', '.join(tags)
		out['results'] = all_tags
		out['success'] = True
	else:
		out['success'] = False
		out['error'] = "Tag data was blank"

	mimetype = 'application/javascript'
	return HttpResponse(json.dumps(out),mimetype)

@csrf_protect
def all_object_comments(request):
	out = { 'results':{},'error':{},'session':{}, 'success': True }
	con = connect_to_mongo('127.0.0.1',27017, "pdfs", "analyst_notes")
	parent_hash = request.GET['parent_hash']
	hashes = []                                                                
	for item in con.find({"parent_hash":parent_hash}):
		rjson = json.dumps(item)
		data = json.loads(rjson)
		hash = data.get("_id")
		hashes.append(hash)

	out['success'] = True
	out['results'] = hashes
	mimetype = 'application/javascript'
	return HttpResponse(json.dumps(out),mimetype)

@csrf_protect
def flag_file(request):
	out = { 'results':{},'error':{},'session':{}, 'success': True }
	con = connect_to_mongo('127.0.0.1',27017, "pdfs", "pdf_repo")
	tag = request.POST['tag']
	con.update({"hash_data.file.md5":request.POST['hash']},{'$addToSet': { "tags":tag} },multi=True)
	out['success'] = True 
	mimetype = 'application/javascript'
	return HttpResponse(json.dumps(out),mimetype)

@csrf_protect
def add_object_comment(request):
	out = { 'results':{},'error':{},'session':{}, 'success': True }
	con = connect_to_mongo('127.0.0.1',27017, "pdfs", "analyst_notes")
	raw_hash = request.POST['raw_hash']
	notes = request.POST['notes']
	parent_hash = request.POST['parent_hash']
	user = request.user.username
	obj = {'_id':raw_hash,'notes':notes,'user':user,'date_time':time(),'parent_hash':parent_hash}
	count = con.find({"_id":raw_hash}).count()
	if count < 1:
		con.insert(obj)
	else:
		con.update({"_id":raw_hash},{"$set": {"notes":notes}},True)

	out['success'] = True
	mimetype = 'application/javascript'
	return HttpResponse(json.dumps(out),mimetype)

@csrf_protect
def get_object_comment(request):
	out = { 'results':{},'error':{},'session':{}, 'success': True }
	con = connect_to_mongo('127.0.0.1',27017, "pdfs", "analyst_notes")
	raw_hash = request.GET['raw_hash']
	data = con.find_one({"_id":raw_hash},{"_id":0,"notes":1})                                                               
	if data != None:
		data = json.dumps(data)
		data = json.loads(data)
		notes = data.get("notes")		
	else:
		notes = ""

	out['success'] = True
	out['results'] =  notes
	mimetype = 'application/javascript'
	return HttpResponse(json.dumps(out),mimetype)

def snatch_data(request):
    hold = []
    out = { 'results':{},'error':{},'session':{} }
    con = connect_to_mongo('127.0.0.1',27017, "pdfs", "malware")
    data = con.find_one({'tags': { '$size': 1 } },{ 'hash_data.file.md5':1,'contents.objects.object.encoded':1,'contents.objects.object.decoded':1,'contents.objects.object.md5':1,'contents.objects.object.suspicious':1,'_id':0})

    if data != None:
        data = json.dumps(data)
        data = json.loads(data)
        hash_data = data.get("hash_data")
        lfile = hash_data.get("file")
        fhash = lfile.get("md5")
        contents = data.get("contents")
        objects = contents.get("objects")
        object = objects.get("object")
    
        for obj in object:
            md5 = obj.get("md5")
            encoded = obj.get("encoded")
            decoded = obj.get("decoded")
            suspicious = obj.get("suspicious")
        
            d = { 'hash':md5,'encoded':encoded,'decoded':decoded, 'suspicious':suspicious }
            hold.append(d)
            
        out['results'] = hold
        out['hash'] = fhash
    else:
        out['error'] = "No more objects"
        
    return render_to_response('flagger.html',out,context_instance=RequestContext(request))
    
@csrf_protect
def flag_data(request):
    out = { 'results':{},'error':{},'session':{}, 'success': True }
    con = connect_to_mongo('127.0.0.1',27017, "pdfs", "malware")
    con.update({"contents.objects.object.md5":request.POST['hash']},{'$set': {'contents.objects.object.$.suspicious':'malicious'}},multi=True)
    con.update({"contents.objects.object.md5":request.POST['hash']},{'$addToSet': { "tags":"checked"} },multi=True)
    out['results'] = request.POST['hash']
    mimetype = 'application/javascript'
    return HttpResponse(json.dumps(out),mimetype)  

@csrf_protect
def skip_data(request):
    out = { 'results':{},'error':{},'session':{}, 'success': True }
    con = connect_to_mongo('127.0.0.1',27017, "pdfs", "malware")
    con.update({"hash_data.file.md5":request.POST['hash']},{'$addToSet': { "tags":"research"} })
    out['results'] = request.POST['hash']
    mimetype = 'application/javascript'
    return HttpResponse(json.dumps(out),mimetype)    
