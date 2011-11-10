__description__ = 'Snatch the SWF!'
__author__ = 'Brandon Dixon'
__version__ = '1.0'
__date__ = '2011/11/07'

import simplejson as json
import optparse
from PDFConsole import PDFConsole
from PDFCore import PDFParser

def snatch(file, out):
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
            offset = objs[index].offset
            size = objs[index].size
            details = objs[index].object
            if details.type == "stream":
                encoded_stream = details.encodedStream
                decoded_stream = details.decodedStream
                is_flash = decoded_stream[:3]
                compare = ["CWS","FWS"]
                flash_match = [s for s in objs if is_flash in compare]
                if flash_match:
                    f = open(out + str(oid) + '_decoded_object.swf',"w")
                    f.write(decoded_stream.strip())
                    f.close()

        count += 1

def main():
    oParser = optparse.OptionParser(usage='usage: %prog [options]\n' + __description__, version='%prog ' + __version__)
    oParser.add_option('-f', '--file', default='', type='string', help='file to build an object from')
    oParser.add_option('-o', '--out', default='', type='string', help='output folder')
    (options, args) = oParser.parse_args()

    if options.file and options.out:
		snatch(options.file, options.out)
    else:
        oParser.print_help()
        return

if __name__ == '__main__':
    main()


