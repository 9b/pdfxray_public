#!/usr/bin/python

import os
import re
import os.path
import sys
import hashlib
import simplejson as json

class cBinaryFile:
    def __init__(self, file):
        self.file = file
        if file == "":
            self.infile = sys.stdin
        else:
            self.infile = open(file, 'rb')
        self.ungetted = []

    def byte(self):
        if len(self.ungetted) != 0:
            return self.ungetted.pop()
        inbyte = self.infile.read(1)
        if not inbyte:
            self.infile.close()
            return None
        return ord(inbyte)

    def bytes(self, size):
        if size <= len(self.ungetted):
            result = self.ungetted[0:size]
            del self.ungetted[0:size]
            return result
        inbytes = self.infile.read(size - len(self.ungetted))
        if inbytes == '':
            self.infile.close()
        result = self.ungetted + [ord(b) for b in inbytes]
        self.ungetted = []
        return result

    def unget(self, byte):
        self.ungetted.append(byte)

    def ungets(self, bytes):
        bytes.reverse()
        self.ungetted.extend(bytes)

def FindPDFHeaderRelaxed(oBinaryFile):
    bytes = oBinaryFile.bytes(1024)
    index = ''.join([chr(byte) for byte in bytes]).find('%PDF')
    if index == -1:
        oBinaryFile.ungets(bytes)
        return ([], None)
    for endHeader in range(index + 4, index + 4 + 10):
        if bytes[endHeader] == 10 or bytes[endHeader] == 13:
            break
    oBinaryFile.ungets(bytes[endHeader:])
    return (bytes[0:endHeader], ''.join([chr(byte) for byte in bytes[index:endHeader]]))

def UpdateWords(word, wordExact, slash, words, hexcode, lastName):
    if word != '':
        if slash + word in words:
            words[slash + word][0] += 1
            if hexcode:
                words[slash + word][1] += 1
        elif slash == '/':
            words[slash + word] = [1, 0]
            if hexcode:
                words[slash + word][1] += 1
        if slash == '/':
            lastName = slash + word
    return ('', [], False, lastName)

def encoder_cleaner(stream_data):
    try:
	json.dumps(stream_data)
	return stream_data
    except:		    
	tmp_stream_data = stream_data.decode('utf-8','replace')

    try:
	json.dumps(tmp_stream_data)
	json.loads(tmp_stream_data)
	return tmp_stream_data
    except:
	stream_data = stream_data.decode('utf-16','replace')
	return stream_data

def PDFiD(file,force=False):
    filename = str(file)
    filesize = str(os.path.getsize(file))
    word = ''
    wordExact = []
    hexcode = False
    lastName = ''
    keywords = ('obj',
                'endobj',
                'stream',
                'endstream',
                'xref',
                'trailer',
                'startxref',
               )
    words = {}
    for keyword in keywords:
        words[keyword] = [0, 0]
    slash = ''

    try:
        oBinaryFile = cBinaryFile(file)
        (bytesHeader, pdfHeader) = FindPDFHeaderRelaxed(oBinaryFile)
        if pdfHeader == None and not force:
	    isPdf = 'False'
            return xmlDoc
        else:
            if pdfHeader == None:
		isPdf = 'False'
                pdfHeader = ''
            else:
		isPdf = 'True'
	    header = repr(pdfHeader[0:10]).strip("'")
        byte = oBinaryFile.byte()
        while byte != None:
            char = chr(byte)
            charUpper = char.upper()
            if charUpper >= 'A' and charUpper <= 'Z' or charUpper >= '0' and charUpper <= '9':
                word += char
                wordExact.append(char)
            elif slash == '/' and char == '#':
                d1 = oBinaryFile.byte()
                if d1 != None:
                    d2 = oBinaryFile.byte()
                    if d2 != None and (chr(d1) >= '0' and chr(d1) <= '9' or chr(d1).upper() >= 'A' and chr(d1).upper() <= 'F') and (chr(d2) >= '0' and chr(d2) <= '9' or chr(d2).upper() >= 'A' and chr(d2).upper() <= 'F'):
                        word += chr(int(chr(d1) + chr(d2), 16))
                        wordExact.append(int(chr(d1) + chr(d2), 16))
                        hexcode = True
                    else:
                        oBinaryFile.unget(d2)
                        oBinaryFile.unget(d1)
                        (word, wordExact, hexcode, lastName) = UpdateWords(word, wordExact, slash, words, hexcode, lastName)
                else:
                    oBinaryFile.unget(d1)
                    (word, wordExact, hexcode, lastName) = UpdateWords(word, wordExact, slash, words, hexcode, lastName)
            else:
                (word, wordExact, hexcode, lastName) = UpdateWords(word, wordExact, slash, words, hexcode, lastName)
                if char == '/':
                    slash = '/'
                else:
                    slash = ''

            byte = oBinaryFile.byte()
        (word, wordExact, hexcode, lastName) = UpdateWords(word, wordExact, slash, words, hexcode, lastName)
    
    except:
	nada = None
       
    keywords = []
    components = []
    
    keys = words.keys()
    keys.sort()
    for word in keys:
	name = word
	count = words[word][0]
	hexCount = words[word][1]
	
	if name[0] == '/' and count > 0:
	    name = encoder_cleaner(name)
	    keyword = { 'count':count, 'hexcodecount':hexCount, 'name':name }
	    keywords.append(keyword)
	else:
	    if count > 0:
		component = { 'count':count, 'hexcodecount':hexCount, 'name':name }
		components.append(component)
			
        data = { 'filesize': filesize, 'filename':filename, 'header':header, 'isPdf':isPdf, 'keywords': { 'keyword': keywords }, 'components': { 'component': components } }
    
    return json.dumps(data)

