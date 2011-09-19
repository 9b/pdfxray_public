import hashlib
import json

def get_hash_data(file, type):
	if type == "md5":
		output = hashlib.md5()
	elif type == "sha1":
		output = hashlib.sha1()
	elif type == "sha256":
		output = hashlib.sha256()
	else:
		output = "Error"
		
	with open(file,'rb') as f: 
	    for chunk in iter(lambda: f.read(8192), ''): 
	         output.update(chunk)
	return output.hexdigest()
	
#build generic object for the file hash data
def get_hash_object(file):
	md5 = get_hash_data(file, "md5")
	sha1 = get_hash_data(file, "sha1")
	sha256 = get_hash_data(file, "sha256")
	
	hashes = { 'md5': md5, 'sha1': sha1, 'sha256': sha256 }
	return hashes