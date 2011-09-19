import sys, os, math
import optparse
import hashlib
import simplejson as json
from numpy import zeros
from PDFConsole import PDFConsole
from PDFCore import PDFParser
from pdfxray.apps.malpdfobj.ent_block import *

def ByteToHex( byteStr ):
    return ''.join( [ "%02X " % ord( x ) for x in byteStr ] ).strip()

def get_entropy(data):
	out = []
	for i in range(0,len(data)):
		key = (i+1)*32
		if key > len(data) + 32:
			break
		chunk = data[i*32:key]
		entropy = float(H(chunk))
		out.append(entropy)
	return out

def H(data):
    if not data:
	return 0
  
    entropy = 0
    len_data = len(data)
    data_counts = zeros(256)
    lord = ord
  
    for d in data:
	data_counts[lord(d)] += 1
  
    for x in range(0, 256):
	p_x = float(data_counts[x])/len_data 
    
	if p_x > 0: 
	    entropy += - p_x*math.log(p_x, 2) 
    
    return entropy

def is_ascii(s):
    return all(ord(c) < 128 for c in s)

def encoder_cleaner(stream_data):
#    try:
#	json.dumps(stream_data)
#	return stream_data
#    except:		    
#	tmp_stream_data = stream_data.decode('utf-8','replace')
#
#    try:
#	json.dumps(tmp_stream_data)
#	json.loads(tmp_stream_data)
#	return tmp_stream_data
#    except:
#	stream_data = stream_data.decode('utf-16','replace')
#	return stream_data

    data = []
    for char in stream_data:
        if is_ascii(char):
            data.append(char)
        else:
            try:
                char = char.decode('utf-8','replace')
                data.append(char)
            except:
                char = char.decode('utf-16','replace')
                data.append(char)

    return ''.join(data)

def snatch_contents(file):
    pdfParser = PDFParser()
    ret,pdf = pdfParser.parse(file, True, False)
    body = pdf.body
    all_objs = []
    for item in body:
	objs = item.objects
	for index in objs:
	    filter = None
	    stream_details = []
	    oid = objs[index].id
	    offset = objs[index].offset
	    size = objs[index].size
	    details = objs[index].object
	    if details.type == "stream":
		decode_error = details.decodingError
		if details.filter != None:
		    filter = details.filter.rawValue
		stream_size = details.size
		encoded_stream = details.encodedStream
		decoded_stream = details.decodedStream

		encoded_md5 = hashlib.md5(encoded_stream).hexdigest()
		decoded_md5 = hashlib.md5(decoded_stream).hexdigest()
		encoded_hex = ByteToHex(encoded_stream)
		decoded_hex = ByteToHex(decoded_stream)
		
		encoded_stream = encoder_cleaner(encoded_stream)
		decoded_stream = encoder_cleaner(decoded_stream)
		    
		js_code = details.JSCode
		temp_entropy = get_entropy(details.rawStream)
		blocks = analyzer(temp_entropy)
		out_entropy = blocks.json_blocks
		stream_details = {'filter': filter,'size':stream_size,'encoded_stream':encoded_stream,'encoded_hash':encoded_md5,'encoded_hex':encoded_hex,'decoded_stream':decoded_stream,'decoded_hash':decoded_md5,'decoded_hex':decoded_hex,'decode_errors':decode_error,'js_code':js_code,'entropy':out_entropy,'flags':[]}
	    is_encrypted = details.encrypted
	    contains_js = details.containsJScode
	    errors = details.errors
	    raw_value = details.rawValue
	    references = details.references
	    try:
	        raw_md5 = hashlib.md5(raw_value).hexdigest()
	    except:
                raw_md5 = "error"
	    raw_value = encoder_cleaner(raw_value)
	    try:
		suspicious_events = details.suspiciousEvents
		suspicious_actions = details.suspiciousActions
		suspicious_elements = details.suspiciousElements
		vulns = details.vulns
	    except:
		suspicious_events = []
		suspicious_actions = []
		suspicious_elements = []
		vulns = []	    
	    temp = {'id':oid,'offset':offset,'size':size,'stream':stream_details,'encrypted':is_encrypted,'contains_js':contains_js,'raw':raw_value,'raw_hash':raw_md5,'references':references,'errors':errors,'suspicious_events':suspicious_events,'suspicious_actions':suspicious_actions,'suspicious_elements':suspicious_elements,'vulns':vulns}
	    all_objs.append(temp)

    return json.dumps(all_objs)

def snatch_version(file):
    pdfParser = PDFParser()
    ret,pdf = pdfParser.parse(file, True, False)
    statsDict = pdf.getStats()
    objs = []
    count = 0
    for version in range(len(statsDict['Versions'])):
	meta = pdf.getBasicMetadata(count)
	author = ""
	creator = ""
	producer = ""
	creation_date = ""
	modification_date = ""
	if meta.has_key('author'):
		author = encoder_cleaner(meta['author'])
	if meta.has_key('creator'):
		creator = encoder_cleaner(meta['creator'])
	if meta.has_key('producer'):
		producer = encoder_cleaner(meta['producer'])
	if meta.has_key('creation'):
		creation_date = encoder_cleaner(meta['creation'])
	if meta.has_key('modification'):
		modification_date = encoder_cleaner(meta['modification'])
	suspicious_events_present = "false"
	suspicious_actions_present = "false"
	suspicious_elements_present = "false"
	vulnerabilities_present = "false"
	statsVersion = statsDict['Versions'][version]
	actions = statsVersion['Actions']
	events = statsVersion['Events']
	vulns = statsVersion['Vulns']
	elements = statsVersion['Elements']
	tmp = statsVersion['Objects'][1]
	object_ids = tmp[1:-1].split(',')
	if events != None or actions != None or vulns != None or elements != None:
	    if events != None:
		suspicious_events_present = "true"
	    if actions != None:
		suspicious_actions_present = "true"
	    if elements != None:
		suspicious_elements_present = "true"
	    if vulns != None:
		vulnerabilities_present = "true"
		
	obj = {'version': version,'object_ids':object_ids,'total_objects':statsVersion['Objects'][0],'author':author,'creator':creator,'producer':producer,'creation_date':creation_date,'modification_date':modification_date,'suspicious_events_present':suspicious_events_present,'suspicious_actions_present':suspicious_actions_present,'suspicious_elements_present':suspicious_elements_present,'vulnerabilities_present':vulnerabilities_present}
	objs.append(obj)
	count += 1
	
    return json.dumps(objs)
