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
from forms import *
from pdfxray.apps.utilities.views import *
from pdfxray.apps.accounts.forms import login_form

@csrf_protect
def standard(request):
	form = SearchForm()
	log_form = login_form()
	sform = SearchOptions()
        return render_to_response('search.html',{'form': form, 'login': log_form,'sform':sform},context_instance=RequestContext(request))

@csrf_protect
def process_search(request):
	search_value = request.POST['search_value']
	search_selection = request.POST['search_selection']
	if search_value == "":
		return HttpResponseRedirect('/error/')	
	elif search_selection == "hashes_md5":
		return HttpResponseRedirect('/report/'+ search_value)
	elif search_selection == "hashes_sha1":
		data = search_by_sha1(search_value)
		if data == None:
			return HttpResponseRedirect('/error/')		
		hash_data = data.get("hash_data")
		file = hash_data.get("file")
		md5 = file.get("md5")
		return HttpResponseRedirect('/report/'+ md5)
	elif search_selection == "hashes_sha256":
		data = search_by_sha256(search_value)
		if data == None:
			return HttpResponseRedirect('/error/')	
		hash_data = data.get("hash_data")
		file = hash_data.get("file")
		md5 = file.get("md5")
		return HttpResponseRedirect('/report/'+ md5)
	elif search_selection == "hashes_object_raw_hash":
		data = search_by_raw_hash(search_value)
		if data == None:
			return HttpResponseRedirect('/error/')	
		hash_data = data.get("hash_data")
		file = hash_data.get("file")
		md5 = file.get("md5")
		#NEED TO RETURN OBJECT NUMBER SOMEHOW
		return HttpResponseRedirect('/report/'+ md5)
	elif search_selection == "hashes_object_encoded_hash":
		data = search_by_encoded_hash(search_value)
		if data == None:
			return HttpResponseRedirect('/error/')	
		hash_data = data.get("hash_data")
		file = hash_data.get("file")
		md5 = file.get("md5")
		#NEED TO RETURN OBJECT NUMBER SOMEHOW
		return HttpResponseRedirect('/report/'+ md5)
	elif search_selection == "hashes_object_decoded_hash":
		data = search_by_decoded_hash(search_value)
		if data == None:
			return HttpResponseRedirect('/error/')	
		hash_data = data.get("hash_data")
		file = hash_data.get("file")
		md5 = file.get("md5")
		#NEED TO RETURN OBJECT NUMBER SOMEHOW
		return HttpResponseRedirect('/report/'+ md5)
	else:
		return HttpResponseRedirect('/error/')	