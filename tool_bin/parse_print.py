import argparse, os, sys
import numpy as np
from libdeda.print_parser import *


class Main(object):

    def argparser(self):
        parser = argparse.ArgumentParser(
            description='Extract Yellow Dots From Printed Pages')
        parser.add_argument("file", type=str, help='Path to Input File')
        parser.add_argument("-m",'--mask', type=str,
            help='If file arg is monochrome mask of dots, specify inked area mask')
        parser.add_argument("-d",'--dpi', default=0, type=int, 
            help='Input image dpi')
        #parser.add_argument("-p",'--pattern', default=None, type=int, 
        #    help='Assume pattern')
        parser.add_argument("-o",'--only-detect', default=False,
            action='store_true', help='Only detect pattern and exit')
        parser.add_argument("-v",'--verbose', action='count', default=0, help='Fehlerausgabe')
        self.args = parser.parse_args()

    def __init__(self):
        self.argparser()
    
    def __call__(self):
        try:
          with open(self.args.file, "rb") as fp:
            pp = PrintParser(fp.read(),ydxArgs=dict(mask=self.args.mask,
                  verbose=max(-1,self.args.verbose-1),inputDpi=self.args.dpi),
              verbose=self.args.verbose)
        except YD_Parsing_Error as e: pattern = None
        else: pattern = pp.pattern
        
        if pattern is None: 
                print("No tracking dot pattern detected. For best results "
                    "try a 300 dpi scan and a lossless file format.")
                return
        print("Detected pattern %s"%pp.pattern)
        if self.args.only_detect: return

        tdm = pp.tdm
        if tdm is None: return
        print(tdm)
        #mask = tdm.createMask()
        #masked = np.array((tdm.aligned+mask.aligned)>0,dtype=np.uint8)
        #print(matrix2str(masked))
        #print(mask)
        print(repr(tdm))
        print("Decoded:")
        decoded = tdm.decode()
        for key in ["manufacturer", "serial", "timestamp", "raw"
                ]+list(decoded.keys()):
            if key not in decoded: continue
            print("\t%s: %s"%(key, decoded.pop(key)))
        #print("Decoded: %s"%str(tdm.decode()))
        """
        print("Anonymised: \n\tSucceeds redundance check: %s"
            %str(tdm.check()))
        try:
            print("\tdecoded: %s"%mask.decode())
        except Exception as e:
            print("\tDecoding error: %s"%repr(e))
        """
        if len(set(pp.validMatrices)) > 1:
            print("\nAll valid TDMS:")
            for tdm in set(pp.validMatrices):
                print("\t%d x %s"%(
                    pp.validMatrices.count(tdm),str(tdm.decode())))


main = lambda:Main()()
if __name__ == "__main__":
    main()
    
