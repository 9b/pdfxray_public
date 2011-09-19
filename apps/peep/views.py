from django.http import HttpResponse
from django.http import HttpResponseRedirect
from django.contrib.auth.models import User, Group
from django.shortcuts import render_to_response, redirect
from django.core.urlresolvers import reverse
from django.core.context_processors import csrf
from django.views.decorators.csrf import csrf_protect
from django.template import RequestContext
from django.conf import settings
from django.core.serializers.json import DjangoJSONEncoder
from django.utils import simplejson
from forms import UploadFileForm
from pymongo import Connection
import sys, os
import optparse
from PDFConsole import PDFConsole
from PDFCore import PDFParser
from pdfxray.apps.malpdfobj.hash_maker import *
from pdfxray.apps.utilities.views import *

import os
import simplejson as json
import pymongo
from time import time


global hash

@csrf_protect
def main(request):
	form = UploadFileForm()
        return render_to_response('index.html',{'form': form},context_instance=RequestContext(request))

@csrf_protect
def process_file(request):
        if request.method == 'POST':
                form = UploadFileForm(request.POST, request.FILES)
                if form.is_valid():
                        data = handle_uploaded_file(request.FILES,request.session,request.user)
                        return HttpResponseRedirect(reverse('peep', args=[hash]))
        
        else:
                data = {'success':False,'error':"Processing failed on file"}

        return render_to_response('report.html', {'results': simplejson.dumps(data, cls=DjangoJSONEncoder)}, context_instance=RequestContext(request))

@csrf_protect
def interact(request,rhash,template_name):
	json = { 'results':{},'error':{},'session':{} }
	
	if request.session.get('store_error'):		
		json['error'] = request.session['store_error']
	
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
				
			isSuspicious(data)
			json['results'] = data
			request.session[rhash] = data
			return render_to_response(template_name,json,context_instance=RequestContext(request))
		
@csrf_protect
def upload_file_form(request):
        form = UploadFileForm()
        return render_to_response('upload.html', {'form': form}, context_instance=RequestContext(request))

def handle_uploaded_file(request,rsesh,ruser):
	global hash
	f = request['file']
	filename = f.name
	destination = open('%s/%s' % (settings.MEDIA_ROOT + '/uploads/', filename), 'wb')
	for chunk in f.chunks():
		destination.write(chunk)
	destination.close()
    
	file = settings.MEDIA_ROOT + '/uploads/' + filename
	hash = get_hash_data(file, "md5") #grab the hash so we can see if the file is present
	is_present = get_sample(hash) #grabs the sample if it is there, if not then it runs
	if is_present == None:
		stored = True
		user = None
		t = time()
		pdfParser = PDFParser()
		ret,data = pdfParser.parse(file, True, False)
		process_time = time() - t
		#data = jPdf(json.loads(output)) #build the class object
		#store_it = store_sample(output) #try and store the raw data
		#if store_it == None:
		#	rsesh['store_error'] = True #we can let the user know if it stored with this (true an error happened)
		#	stored = False
			
		if ruser.is_authenticated:
			user = ruser.username
		else:
			user = "annonymous"

		fstat = { 'date_time':time(),'filename':filename,'stored':stored,'process_time':process_time,'user':user,'hash':hash }
		store_file_stats(json.dumps(fstat))
	else:
		data = is_present #the file was present and returned

	rsesh[hash] = data #throw the class object in the session to avoid DB hits
	
	return data

