#!/usr/bin/python
import os, sys, traceback
import numpy
import matplotlib
from pylab import plot, bar, figure, show
from numpy.fft import *

__author__ = "Matthew Wollenweber"
__email__ = "mjw@cyberwart.com"
__copyright = "Mathew Wollenweber 2011"

gauss = [.006, .061, .242, .383, .242, .061, .006]
objects = []

class analyzer():
    def __init__(self, in_data = []):
        #data has values and offset.
        self.data = []
	self.json_blocks = []
        self.chunk_size = 32
        self.json_blocks = self.in_process(in_data)
        self.original = None
        
    def blur(self, data):
        lnth = len(data)
        out = []
        
        for i in range(0, len(data)):
            smooth_val = 0
            if i-3 >= 0:
                smooth_val += data[i-3] * gauss[0]
            else:
                smooth_val += data[i] * gauss[0]
            if i-2 >= 0:
                smooth_val += data[i-2] * gauss[1]
            else:
                smooth_val += data[i] * gauss[1]
            if i-1 >= 0:
                smooth_val += data[i-1] * gauss[2]
            else:
                smooth_val += data[i] * gauss[2]
                
            smooth_val += data[i] * gauss[3]
            
            if i+1 < lnth:
                smooth_val += data[i+1] * gauss[4]
            else:
                smooth_val += data[i] * gauss[4]
            if i+2 < lnth:    
                smooth_val += data[i+2] * gauss[5]
            else:
                smooth_val += data[i] * gauss[5]
            if i+3 < lnth:
                smooth_val += data[i+3] * gauss[6]
            else:
                smooth_val += data[i] * gauss[6]
                
            out.append(smooth_val)
        return out
        
        
    def in_process(self, in_data):
        just_data = []
        for line in in_data:
#            [d, offset] = line.split(",")
#            d = float(d)
            d = float(line)
            offset = 0
                           
            just_data.append(d)
            self.data.append([offset, d])
            
        self.original = just_data
        just_data = self.blur(just_data)
        just_data = self.blur(just_data)
#        just_data = self.blur(just_data)
        self.data = just_data

        ndata = numpy.array(just_data)
        self.ndata = ndata
            
#        self.maximum = numpy.max(ndata)
#        self.minimum = numpy.min(ndata)
        self.std_dev = numpy.std(ndata)
        self.mean = numpy.mean(ndata)
        self.length = len(ndata)
        self.data_size = self.length * self.chunk_size
        
        objects = self.get_chunks(just_data)
#        self.display_graph(self.original, just_data)
#        self.get_freq(just_data)
	return objects
        
    def get_chunks(self, data = None):
        if data == None:
            data = self.data
	self.json_blocks = []
	objects = []
        blocks = []
        str_list = []
        std = self.std_dev
        last = -10000
        block_size = 0
        block_sum = 0
        ct = 0
        
        for i in range(0, len(data)):
            block_size += 1
            offset = i * self.chunk_size
            cur = data[i]
            
            if abs(cur - last) > (std * 0.50) and last >= 0:
#                print "BLOCK[%s]: offset = %s size = %s mean=%s" % (ct, offset, block_size, (block_sum+cur)/block_size)
		obj = { 'block':ct,'offset':offset,'size':block_size,'mean':(block_sum+cur)/block_size }
                objects.append(obj)
                ct += 1
                block_size = 0
                block_sum = 0
            else:
                #no new chunk
                block_sum += cur
                
            last = cur                   

	return objects

    def display_graph(self, data1, data2):
        #plot(range(0, len(data1)), data1)
        #bar(range(0, len(data1)), data1)
        fig = figure()
        rg = range(0, len(data1))
        plot(rg, data1,rg, data2, color='k')
#        show()

    def get_freq(self, data = None):
        if data == None:
            data = self.data
            
        fourier = rfft(data)
        N = len(data)
        timestep = 0.5
        freq = fftfreq(N, d = timestep)
        #print "frequencies: "
#        print freq
#        print fourier
        
        
def main(filename):
    data = []
    f = open(filename, "r")
    for line in f:
        data.append(line)
        
    my_analyzer = analyzer(data)
    f.close()
    print my_analyzer.json_blocks
    
if __name__ == "__main__":
    main(sys.argv[1])

        
