from django.http import HttpResponse
from django.http import HttpResponseRedirect
from django.contrib.auth.models import User, Group
from django.shortcuts import render_to_response, redirect
from django.core.urlresolvers import reverse
from django.core.context_processors import csrf
from django.views.decorators.csrf import csrf_protect, csrf_exempt
from django.template import RequestContext
from django.conf import settings
from django.core.serializers.json import DjangoJSONEncoder
from django.utils import simplejson
import matplotlib
import matplotlib.cbook
from pdfxray.apps.malpdfobj.object_builder import *
from pdfxray.apps.malpdfobj.malobjclass import *
from pdfxray.apps.malpdfobj.hash_maker import *
from pdfxray.apps.malpdfobj.related_entropy import *
from pdfxray.apps.utilities.views import *
from forms import UploadFileForm
from pdfxray.apps.accounts.forms import login_form
from pymongo import Connection

import os
import ghostscript
import sys
import simplejson as json
import pymongo
from time import time


@csrf_protect
def main(request):
	form = UploadFileForm()
	log_form = login_form()
        return render_to_response('index.html',{'form': form, 'login': log_form},context_instance=RequestContext(request))

@csrf_protect
def about(request):
	form = UploadFileForm()
	log_form = login_form()
        return render_to_response('about.html',{'form': form, 'login': log_form},context_instance=RequestContext(request))

@csrf_protect
def accounts(request):
	form = UploadFileForm()
	log_form = login_form()
        return render_to_response('accounts.html',{'form': form, 'login': log_form},context_instance=RequestContext(request))

@csrf_protect
def handle_error(request):
	json = { 'results':{},'error':{},'session':{},'login':{} }
	json['error'] = "The page you request doesn't exist"
	return render_to_response('error.html',json, context_instance=RequestContext(request))	

@csrf_protect
def process_file(request):
	json = { 'results':{},'error':{},'session':{},'login':{} }
	log_form = login_form()
        if request.method == 'POST':
                form = UploadFileForm(request.POST, request.FILES)
                if form.is_valid():
                        data = handle_uploaded_file(request.FILES,request.session,request.user)
			hash = data.file_md5
                        return HttpResponseRedirect(reverse('report', args=[hash]))
		else:
			json['error'] = "no file found"
			return render_to_response('error.html',json, context_instance=RequestContext(request))
        
        else:
		json['error'] = "processing file failed"
		return render_to_response('error.html',json, context_instance=RequestContext(request))

        return render_to_response('report.html', {'results': simplejson.dumps(data, cls=DjangoJSONEncoder), 'login': log_form}, context_instance=RequestContext(request))

@csrf_protect
def interact(request,rhash,template_name):
	json = { 'results':{},'error':{},'session':{},'login':{} }
	log_form = login_form()
	json['login'] = log_form
	error_text = rhash + '_store_error'
	if request.session.get(error_text):		
		json['error'] = request.session[error_text]
	
	if request.session.get(rhash):
		json['results'] = request.session[rhash]
		return render_to_response(template_name,json,context_instance=RequestContext(request))
	else:
	
		data = get_sample(rhash)
		if data == None:
			json['error'] = "File not yet uploaded"
			return render_to_response('error.html',json, context_instance=RequestContext(request))
		else:
			has_related = contains_related(data.file_md5)
			if has_related == False:	
				related_data = generate_related(data) #get the related in JSON form
				data.add_related(related_data) #send that to the object for processing
				upsert_related_sample(data.file_md5,related_data) #update the mongo record with the related data
				
			json['results'] = data
			request.session[rhash] = data
			return render_to_response(template_name,json,context_instance=RequestContext(request))
		
@csrf_protect
def upload_file_form(request):
        form = UploadFileForm()
	log_form = login_form()
        return render_to_response('upload.html', {'form': form, 'login': log_form},context_instance=RequestContext(request))

def handle_uploaded_file(request,rsesh,ruser):
	stored = True
	process_time = None
	f = request['file']
	filename = f.name
	destination = open('%s/%s' % (settings.MEDIA_ROOT + '/uploads/', filename), 'wb')
	for chunk in f.chunks():
		destination.write(chunk)
	destination.close()
    
	file = settings.MEDIA_ROOT + '/uploads/' + filename
	hash = get_hash_data(file, "md5") #grab the hash so we can see if the file is present

	image_path = settings.MEDIA_ROOT + '/previews/' + hash + ".png"
	args = ["-dSAFER","-dBATCH","-dNOPAUSE","-sDEVICE=png16m","-r300","-dFirstPage=1","-dLastPage=1","-sOutputFile=" + image_path,file]
	try:
		ghostscript.Ghostscript(*args)
		image_generation = True
	except:
		image_generation = False
	
	is_present = get_sample(hash) #grabs the sample if it is there, if not then it runs
	if is_present == None:
		user = None
		t = time()
		output = build_obj(file) #build the raw object
		process_time = time() - t
		data = jPdf(json.loads(output)) #build the class object
		store_it = store_sample(output) #try and store the raw data
		if store_it == None:
			error_text = hash + '_store_error'
			rsesh[error_text] = True #we can let the user know if it stored with this (true an error happened)
			stored = False
	else:
		data = is_present #the file was present and returned
		
	if ruser.is_authenticated:
		user = ruser.username
	else:
		user = "annonymous"

	fstat = { 'date_time':time(),'filename':filename,'filesize':int(data.filesize),'stored':stored,'process_time':process_time,'user':user,'hash':data.file_md5 } #'remote_addr':request.META['REMOTE_ADDR']
	store_file_stats(json.dumps(fstat))

	has_related = contains_related(data.file_md5)
	if has_related == False:	
		related_data = generate_related(data) #get the related in JSON form
		data.add_related(related_data) #send that to the object for processing
		upsert_related_sample(data.file_md5,related_data) #update the mongo record with the related data
		
	rsesh[hash] = data #throw the class object in the session to avoid DB hits
	
	return data

