import pdfparser
import simplejson as json

def contents(file):
	PDF_ELEMENT_INDIRECT_OBJECT = 2
	oPDFParser = pdfparser.cPDFParser(file)
	cntComment = 0
	cntXref = 0
	cntTrailer = 0
	cntStartXref = 0
	cntIndirectObject = 0
	dicObjectTypes = {}
	content_json_objs = [] #9bplus
	
	selectComment = True
	selectXref = True
	selectTrailer = True
	selectStartXref = True
	selectIndirectObject = True
	
	while True:
	    object = oPDFParser.GetObject()
	    if object != None:
			if object.type == PDF_ELEMENT_INDIRECT_OBJECT and selectIndirectObject:
				content_json_objs.append(pdfparser.content2JSON(object))
	    else:
		    break	
	
	data = { 'object': content_json_objs }
	result = json.dumps(data)
	return result
