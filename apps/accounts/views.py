from django.contrib.auth.models import User, Group
from django.contrib.auth import authenticate, login, logout
from django.shortcuts import render_to_response, redirect
from django.core.serializers.json import DjangoJSONEncoder
from django.template import RequestContext
from django.http import HttpResponse
from django.utils import simplejson
from pdfxray.apps.accounts.forms import register_form, login_form
from pdfxray.apps.core.forms import UploadFileForm
from pdfxray.apps.reports.views import by_user
from pdfxray.apps.accounts.models import user_profile
from pdfxray.apps.core.forms import UploadFileForm
from pdfxray.apps.accounts.forms import login_form
import string, random, hashlib

def show_login(request):
    form = login_form()
    return render_to_response('login.html',{'form': form},context_instance=RequestContext(request))

def show_register(request):
    form = register_form()
    return render_to_response('register.html',{'form': form},context_instance=RequestContext(request))

def handle_logout(request):
    logout(request)
    form = UploadFileForm()
    log_form = login_form()
    return render_to_response('index.html',{'form': form, 'login': log_form},context_instance=RequestContext(request))

def handle_login(request):
    json = {
        'errors': {},
        'text': {},
        'success': False,
    }
    
    form = login_form(request.POST)
    if form.is_valid():
	user = authenticate(username=request.POST['username'],
	                    password=request.POST['password'])
    
	if user is not None:
	    if user.is_active:
		login(request, user)
		form = UploadFileForm()
		return render_to_response('index.html',{'form': form},context_instance=RequestContext(request))
	    else:
		# Return a 'disabled account' error message
		json['error']= 'Account disabled.'
		return render_to_response('error.html',json, context_instance=RequestContext(request))
	else:
	    # Return an 'invalid login' error message.
	    json['error'] = 'Username and/or password invalid.'
	    return render_to_response('error.html',json, context_instance=RequestContext(request))
    
    else:
	    json['error'] = "Please fill in all fields"
	    return render_to_response('error.html',json, context_instance=RequestContext(request))
		
    return HttpResponse(simplejson.dumps(json, cls=DjangoJSONEncoder))

def handle_register(request):

    json = {
            'error': {},
            'text': {},
            'success': False,
    }

    form = register_form(request.POST)
    if form.is_valid():
	username = request.POST['username']
	first = request.POST['first']
	last = request.POST['last']
	company = request.POST['company']
	email = request.POST['email']
	password = request.POST['password']
	confirm_password = request.POST['confirm_password']

	if password == confirm_password:
	    user, created = User.objects.get_or_create(first_name = first, last_name = last, username = username, email = email)
	    standard_users = Group.objects.get(name="standard_users")
	    if created:
		user.set_password(password)
		user.groups.add(standard_users)
		user.is_active = True
		user.save()

		key = hashlib.sha224(username + email + ''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(10))).hexdigest()
		
		profile = user_profile(api_key=key,company=company,user=user)
		profile.save()

		json['success'] = True
		json['text'] = "Registration successful"
		form = UploadFileForm()
		log_form = login_form()
		return render_to_response('index.html',{'form': form,'login':log_form},context_instance=RequestContext(request))
	    else:
		json['success'] = False
		json['error'] = "Username already taken"
		return render_to_response('error.html',json, context_instance=RequestContext(request))

	else:
	    json['success'] = False
	    json['error'] = "Passwords do not match"
	    return render_to_response('error.html',json, context_instance=RequestContext(request))

    else:
	    json['error'] = form.errors
	    return render_to_response('error.html',json, context_instance=RequestContext(request))

    return HttpResponse(simplejson.dumps(json, cls=DjangoJSONEncoder))

def my_account_details(request):
    output = { 'results':{},'error':{},'session':{} }
    if request.user.is_authenticated():
	user = User.objects.get(username=request.user.username)
	reports = by_user(request.user.username)
	profile = user.get_profile()
	api_key = profile.get_api_key()
	output['username'] = request.user.username
	output['reports'] = reports
	output['api_key'] = api_key
	return render_to_response('my_account.html',output,context_instance=RequestContext(request))
    else:
	output['error'] = "You must login to view your account"
	return render_to_response('error.html',output, context_instance=RequestContext(request))