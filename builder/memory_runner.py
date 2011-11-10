__description__ = 'Analyzes Malicious PDF Object in Memory'
__author__ = 'Brandon Dixon'
__version__ = '1.0'
__date__ = '2011/11/07'

from object_builder import *
import simplejson as json
import optparse
import malobjclass
import codecs

#user defined actions here
def user_land(pdf):
	print pdf.file_md5

def main():
	oParser = optparse.OptionParser(usage='usage: %prog [options]\n' + __description__, version='%prog ' + __version__)
	oParser.add_option('-f', '--file', default='', type='string', help='file to build an object from')
	oParser.add_option('-d', '--dir', default='', type='string', help='dir to build an object from')
	(options, args) = oParser.parse_args()
	
	if options.file:
		output = build_obj(options.file)
		pdf = malobjclass.jPdf(json.loads(output))
		user_land(pdf)
	elif options.dir:
		files = []
		pdfs = []
		dirlist = os.listdir(options.dir)
		for fname in dirlist:
			files.append(fname)
		files.sort()
		for file in files:
			print "[+] Analyzing file " + file
			output = build_obj(options.dir + file)
			pdf = malobjclass.jPdf(json.loads(output))
			pdfs.append(pdf)
		
		user_land(pdfs)    
	else:
		oParser.print_help()	
		return
                                
if __name__ == '__main__':
	main()
