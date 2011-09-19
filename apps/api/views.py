from django.http import HttpResponse
from django.http import HttpResponseRedirect
from django.shortcuts import render_to_response, redirect
from django.core.urlresolvers import reverse
from django.core.context_processors import csrf
from django.views.decorators.csrf import csrf_protect, csrf_exempt
from django.template import RequestContext
from django.core import serializers
from django.conf import settings
from django.core.serializers.json import DjangoJSONEncoder
from django.utils import simplejson
from pdfxray.apps.utilities.views import *
from pdfxray.apps.malpdfobj.object_builder import *
from pdfxray.apps.malpdfobj.malobjclass import *
from pdfxray.apps.malpdfobj.hash_maker import *
from pdfxray.apps.malpdfobj.related_entropy import *
from pdfxray.apps.accounts.forms import login_form
from pdfxray.apps.accounts.views import user_profile
from models import api_statistics
from django.conf import settings
from time import time

def main(request):
	log_form = login_form()
        return render_to_response('api.html',{'login': log_form},context_instance=RequestContext(request))

@csrf_exempt
def submit_file(request):
	out_data = { 'errors':{},'report_permalink':{} }
	stored = True
	process_time = None
	f = request.FILES['file']
	filename = f.name
	destination = open('%s/%s' % (settings.MEDIA_ROOT + '/uploads/', filename), 'wb')
	for chunk in f.chunks():
		destination.write(chunk)
	destination.close()
    
	file = settings.MEDIA_ROOT + '/uploads/' + filename
	hash = get_hash_data(file, "md5") #grab the hash so we can see if the file is present
	is_present = get_sample(hash) #grabs the sample if it is there, if not then it runs
	if is_present == None:
		user = None
		t = time()
		output = build_obj(file) #build the raw object
		process_time = time() - t
		data = jPdf(json.loads(output)) #build the class object
		store_it = store_sample(output) #try and store the raw data
		if store_it == None:
			out_data['errors'] = "file was too large to store"
	else:
		data = is_present #the file was present and returned

	out_data['report_permalink'] = 'http://www.pdfxray.com/report/' + data.file_md5  + '/'
	fstat = { 'date_time':time(),'filename':filename,'filesize':int(data.filesize),'stored':stored,'process_time':process_time,'user':"annonymous",'hash':data.file_md5 }
	store_file_stats(json.dumps(fstat))
	
        mimetype = 'application/javascript'
        return HttpResponse(json.dumps(out_data),mimetype)

@csrf_exempt
def get_full(request,rhash):
	out_data = { 'results':{},'errors':{},'report_permalink':{} }
	if is_key_valid(request):
		data = fetch_raw_data(rhash)
		if data != None:
			out_data['results'] = data
			out_data['report_permalink'] = 'http://www.pdfxray.com/report/' + rhash + '/'
		else:
			out_data['errors'] = "File not found"
	else:
		out_data['errors'] = "API key not valid"
		
        mimetype = 'application/javascript'
        return HttpResponse(json.dumps(out_data),mimetype)

@csrf_exempt
def get_hash_data(request,rhash):
	out_data = { 'results':{},'errors':{},'report_permalink':{} }
	if is_key_valid(request):
		data = fetch_hash_data(rhash)
		if data != None:
			hash_data = data.get("hash_data")
			file = hash_data.get("file")
			out_data['results'] = file
			out_data['report_permalink'] = 'http://www.pdfxray.com/report/' + rhash + '/'
		else:
			out_data['errors'] = "File not found"
	else:
		out_data['errors'] = "API key not valid"
		
	mimetype = 'application/javascript'
	return HttpResponse(json.dumps(out_data),mimetype)

@csrf_exempt
def get_structure(request,rhash):
	out_data = { 'results':{},'errors':{},'report_permalink':{} }
	if is_key_valid(request):
		data = fetch_structure(rhash)
		if data != None:
			structure = data.get("structure")
			out_data['results'] = structure
			out_data['report_permalink'] = 'http://www.pdfxray.com/report/' + rhash + '/'
		else:
			out_data['errors'] = "File not found"
	else:
		out_data['errors'] = "API key not valid"
		
	mimetype = 'application/javascript'
	return HttpResponse(json.dumps(out_data),mimetype)

@csrf_exempt
def get_scans(request,rhash):
	out_data = { 'results':{},'errors':{},'report_permalink':{} }
	if is_key_valid(request):
		data = fetch_scans(rhash)
		if data != None:
			scans = data.get("scans")
			out_data['results'] = scans
			out_data['report_permalink'] = 'http://www.pdfxray.com/report/' + rhash + '/'
		else:
			out_data['errors'] = "File not found"
	else:
		out_data['errors'] = "API key not valid"
		
	mimetype = 'application/javascript'
	return HttpResponse(json.dumps(out_data),mimetype)

@csrf_exempt
def get_contents(request,rhash):
	out_data = { 'results':{},'errors':{},'report_permalink':{} }
	if is_key_valid(request):
		data = fetch_contents(rhash)
		if data != None:
			contents = data.get("contents")
			out_data['results'] = contents
			out_data['report_permalink'] = 'http://www.pdfxray.com/report/' + rhash + '/'
		else:
			out_data['errors'] = "File not found"
	else:
		out_data['errors'] = "API key not valid"
		
	mimetype = 'application/javascript'
	return HttpResponse(json.dumps(out_data),mimetype)
	
@csrf_exempt
def get_object(request,rhash,robj):
        out = None
        data = get_sample(rhash)
        for obj in data.objs:
                if int(obj.id) == int(robj):
                        out = {'id':obj.id, 'version': obj.version, 'type':obj.type }
                        
        if out == None:
                out = {'error':'object ID not found in file'}
                        
        mimetype = 'application/javascript'
        return HttpResponse(json.dumps(out),mimetype)   

@csrf_exempt
def get_report(request,rhash):
        out = None
	out_data = { 'results':{},'errors':{},'report_permalink':{} }
	suspicious_objects = []
	large_objects = []
	if is_key_valid(request):
		data = get_sample(rhash)
		if data != None:
			general = {'md5':data.file_md5,'sha1':data.file_sha1,'sha256':data.file_sha256,'header':data.header,'filesize':data.filesize}
			for obj in data.suspicious_objs:
				out = {'raw_data':obj.raw,'stream':obj.stream_decoded_stream,'stream_hex':obj.stream_decoded_hex,'suspicious_actions':obj.suspicious_actions,'suspicious_events':obj.suspicious_events,'suspicious_elements':obj.suspicious_elements,'vulnerabilities':obj.vulns}
				suspicious_objects.append(out)
			for obj in data.large_objs:
				out = {'raw_data':obj.raw,'stream':obj.stream_decoded_stream,'stream_hex':obj.stream_decoded_hex,'suspicious_actions':obj.suspicious_actions,'suspicious_events':obj.suspicious_events,'suspicious_elements':obj.suspicious_elements,'vulnerabilities':obj.vulns}
				large_objects.append(out)
				
			full = {'general_data':general,'suspicious_objects':suspicious_objects,'large_objects':large_objects,'scan_data':data.virustotal_scan_results}
			out_data['results'] = full
			out_data['report_permalink'] = 'http://www.pdfxray.com/report/' + rhash + '/'
		else:
			out_data['errors'] = 'file was not found'
	else:
		out_data['errors'] = 'API key not valid'
                        
        mimetype = 'application/javascript'
        return HttpResponse(json.dumps(out_data),mimetype) 

def is_key_valid(request):
	try:
		key = request.POST['key']
		#check the key against a form
		profile = user_profile.objects.filter(api_key=key)
		if len(profile) > 0:
			try:
				check = api_statistics.objects.get(api_key=key)
#				if check.count > 50:
#					return False
#				else:
				check.count +=1
				check.save()
			except:
				api = api_statistics(api_key=key,remote_address=request.META['REMOTE_ADDR'],count=1)
				api.save()
			
			return True
		else:
			return False
	except:
		return False
	
	
        
