

class isSuspicious():
    def __init__(self, ipdf):
	self._checks = []
	self._likely_malicious = False
	self._suspicious = False
	self._unlikely_malicious = False
	self._judgement = None
	
	#likely malicious
	self._scan_results = False
	self._related_to_malicious = False
	self._shellcode = False
	self._obfuscation = False
	self._exploits = False
	
	#suspicious
	self._named_functions = False
	self._object_streams = False
	self._filesize = False
	self._matching_components = False
	self._functions_in_objects = False
	self._page_amount = False
	self._flash_present = False
	
	#not likely
	self._javascript = False
	self._no_object_streams = False
	self._uncommon_filters = False
	
	self.pdf_check_suspicious(ipdf)
	self._judgement = self.make_judgement()
	
	ipdf.set_judgement = self._judgement
	
    def make_judgement(self):
	self._likely = self._scan_results or self._related_to_malicious or self._shellcode or self._obfuscation or self._exploits
	self._suspicious = self._named_functions or self._object_streams or self._filesize or self._matching_components or self._functions_in_objects or self._page_amount or self._javascript

	if self._suspicious == True:
	    self._judgement = "Suspicious"
	elif self._likely == True:
	    self._judgement = "Likely Malicious"
	else:
	    self._judgement = "Unlikely Malicious"
	    
    def pdf_check_suspicious(self,ipdf):
	for iobj in ipdf.objs:
	    self.obj_check_suspicious(iobj)
	    
	for result in ipdf.virustotal_scan_results:
	    if result != "":
		self._scan_results = True
		break
	    
	if len(ipdf.suspicious_keywords) > 0:
	    self._named_functions = True
	    
    def obj_check_suspicious(self,iobj):
	if iobj.type == "/ObjStm":
	    self._object_streams = True
	    
        self._checks = self.check_raw_content(iobj.encoded, self._checks) #check encoded for matches
	self._checks = self.check_raw_content(iobj.decoded, self._checks) #check decoded for matches
	self._suspicious = self.f7(self._checks) #get unique outcome
        iobj.suspicious = self._suspicious
	
    def f7(self,seq):
	seen = set()
	seen_add = seen.add
	return [ x for x in seq if x not in seen and not seen_add(x)]
    
    def check_raw_content(self,content,suspicious):
	generic_shellcode ['%[a-z]....', '%[a-z]..', '\[a-z][0-9][0-9]','[a-z]\d{2}']
	generic_flash = ['flash', 'swf']
	generic_adobe = ['app.','/js','/javascript','/JavaScript','/openAction','viewerVersion']
	generic_js = ['.this','function', 'eval', 'unescape\(', '.replace','.substring','fromCharCode','byteToChar','toString','setTimeOut']
	utilprintf = ['util.printf','printf'] #CVE-2008-2992
	geticon = ['getIcon'] #CVE-2009-0927
	customdict = ['spell.', 'customDictionaryOpen','DictionaryOpen'] #CVE-2009-1493
	getannots = ['getAnnots','nnots\('] #CVE-2009-1492
	libtiff = ['image/tif', 'tif"'] #CVE-2010-0188
	newplayer = ['media.newPlayer','.newPlayer'] #CVE-2009-4324
	collectemail = ['collectEmailInfo'] #CVE-2008-0655
	jbig2decode = ['2Decode'] #CVE-2009-0658

	for a in generic_shellcode:
		if re.search(a,content):
			obj = 'shellcode'
			suspicious.append(obj)
			self._shellcode = True
			break
	for a in generic_flash:
		if re.search(a,content):
			obj = 'flash/swf'
			suspicious.append(obj)
			self._flash_present = True
			break
	for a in generic_adobe:
		if re.search(a,content):
			obj = 'adobe calls'
			suspicious.append(obj)
			break
	for a in generic_js:
		if re.search(a,content):
			obj = 'javascript'
			suspicious.append(obj)
			self._javascript = True
			break
	for a in utilprintf:
		if re.search(a,content):
			obj = 'util.printf exploit'
			suspicious.append(obj)
			self._exploits = True
			break
	for a in geticon:
		if re.search(a,content):
			obj = 'getIcon exploit'
			suspicious.append(obj)
			self._exploits = True
			break
	for a in customdict:
		if re.search(a,content):
			obj = 'customdict exploit'
			suspicious.append(obj)
			self._exploits = True
			break
	for a in getannots:
		if re.search(a,content):
			obj = 'getAnnots exploit'
			suspicious.append(obj)
			self._exploits = True
			break
	for a in libtiff:
		if re.search(a,content):
			obj = 'libtiff exploit'
			suspicious.append(obj)
			self._exploits = True
			break
	for a in newplayer:
		if re.search(a,content):
			obj = 'newplayer exploit'
			suspicious.append(obj)
			self._exploits = True
			break
        for a in collectemail:
                if re.search(a,content):
                        obj = 'collectEmail exploit'
                        suspicious.append(obj)
			self._exploits = True
                        break
        for a in jbig2decode:
                if re.search(a,content):
                        obj = 'JBIG2Decode exploit'
                        suspicious.append(obj)
			self._exploits = True
                        break

	return suspicious
    
    def set_judgement(self,judgement):
	self._judgement = judgement
	
    def get_judgement(self):
	return self._judgement
    
    judgement = property(get_judgement,set_judgement)