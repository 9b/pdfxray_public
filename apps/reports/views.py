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
import matplotlib
import matplotlib.cbook
from pdfxray.apps.malpdfobj.object_builder import *
from pdfxray.apps.malpdfobj.malobjclass import *
from pdfxray.apps.malpdfobj.hash_maker import *
from pdfxray.apps.malpdfobj.related_entropy import *
from pdfxray.apps.utilities.views import *
import simplejson as json
from datetime import datetime
from pdfxray.apps.accounts.forms import login_form
from operator import itemgetter

def all_malicious(request):
    log_form = login_form()
    if request.user.is_authenticated():
        user = User.objects.get(username=request.user.username)
        if user.groups.filter(name="standard_users").count() > 0:           
            output = { 'results':{},'error':{},'session':{},'login':{} }
            output['login'] = log_form
            con = connect_to_mongo('127.0.0.1',27017, "pdfs", "malware")
            objs = []
            for data in con.find({},{'structure.filesize':1,'hash_data.file.md5':1,'_id':0}):
                data = json.dumps(data)
                data = json.loads(data)
                hash_data = data.get("hash_data")
                mfile = hash_data.get("file")
                mhash = mfile.get("md5")
                structure = data.get("structure")
                filesize = structure.get("filesize")
                obj = {'filesize':filesize,'hash':mhash}
                objs.append(obj)
                
            output['results'] = objs
            return render_to_response('reports.html',output,context_instance=RequestContext(request))
        else:
            output = { 'results':{},'error':{},'session':{} }
            output['error'] = "You must have a premium account to view this"
            return render_to_response('error.html',output, context_instance=RequestContext(request))
        
def last_fifty(request):
    count = 0
    log_form = login_form()
    output = { 'results':{},'error':{},'session':{},'login':{} }
    output['login'] = log_form
    con = connect_to_mongo('127.0.0.1',27017, "pdfs", "file_statistics")
    objs = []
    res = con.group(['hash'],None,{'initial':[]},'function(obj,prev) { prev.filesize = obj.filesize; prev.hash = obj.hash; prev.date_time = obj.date_time; }')
    #for data in con.find({},{'date_time':1,'filesize':1,'hash':1,'_id':0}).sort('date_time',pymongo.DESCENDING).limit(50):
    for data in res:
        data = json.dumps(data)
        data = json.loads(data)
        mhash = data.get("hash")
        try:
            filesize = int(data.get("filesize"))
        except:
            filesize = "n/a"
        timestamp = data.get("date_time")
        date_obj = datetime.fromtimestamp(timestamp)
        date_time = str(date_obj)
        obj = {'date_time':date_time,'filesize':filesize,'hash':mhash}
        objs.append(obj)
        
    fobjs = sorted(objs, key=itemgetter('date_time'),reverse=True)
    output['results'] = fobjs[0:50]
    return render_to_response('reports.html',output,context_instance=RequestContext(request))

def by_user(user):
    con = connect_to_mongo('127.0.0.1',27017, "pdfs", "file_statistics")
    data_con = connect_to_mongo('127.0.0.1',27017, "pdfs", "test")
    objs = []
    for data in con.find({"user":user},{'date_time':1,'filesize':1,'hash':1,'stored':1,'_id':0}).sort('date_time',pymongo.DESCENDING):
        malicious = "not marked"
        data = json.dumps(data)
        data = json.loads(data)
        mhash = data.get("hash")
        filesize = data.get("filesize")
        timestamp = data.get("date_time")
        stored = data.get("stored")
        date_obj = datetime.fromtimestamp(timestamp)
        date_time = str(date_obj)
        pres = data_con.find({"hash_data.file.md5":mhash,"contents.objects.stream.flags.user":user}).count()
        if pres == 1:
            #for item in data_con.find({"hash_data.file.md5":mhash,"contents.objects.stream.flags.user":user},{"contents.objects.stream.flags.malicious":1,"_id":0}):
                #tmp = json.dumps(data)
                #tmp = json.loads(data)
            malicious = "marked"
        obj = {'date_time':date_time,'filesize':filesize,'hash':mhash,'flagged_malicious':malicious,'stored':stored}
        objs.append(obj)

    return objs