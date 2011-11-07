__description__ = 'Snatch the SWF!'
__author__ = 'Brandon Dixon'
__version__ = '1.0'
__date__ = '2011/11/07'

import simplejson as json
import optparse
from PDFConsole import PDFConsole
from PDFCore import PDFParser

def snatch(file, object_ids, out):
    pdfParser = PDFParser()
    ret,pdf = pdfParser.parse(file, True, False)
    statsDict = pdf.getStats()
    objs = []
    count = 0
    for version in range(len(statsDict['Versions'])):
        body = pdf.body[count]
        objs = body.objects

        for index in objs:
            oid = objs[index].id
            match = [s for s in object_ids if str(oid) in s]
            if match:
                offset = objs[index].offset
                size = objs[index].size
                details = objs[index].object
                if details.type == "stream":
                    encoded_stream = details.encodedStream
                    decoded_stream = details.decodedStream
                    is_flash = decoded_stream[:3]
                    compare = ["CWS","FWS"]
                    flash_match = [s for s in object_ids if is_flash in compare]
                    if flash_match:
                        f = open(out + str(oid) + '_decoded_object.swf',"w")
                        f.write(decoded_stream)
                        f.close()

        count += 1

def main():
    oParser = optparse.OptionParser(usage='usage: %prog [options]\n' + __description__, version='%prog ' + __version__)
    oParser.add_option('-f', '--file', default='', type='string', help='file to build an object from')
    oParser.add_option('-i', '--object', default='', type='string', help='object to grab')
    oParser.add_option('-o', '--out', default='', type='string', help='output folder')
    (options, args) = oParser.parse_args()

    if options.file and options.object and options.out:
		obj_ids = options.object.split(",")
		snatch(options.file, obj_ids, options.out)
    else:
        oParser.print_help()
        return

if __name__ == '__main__':
    main()


