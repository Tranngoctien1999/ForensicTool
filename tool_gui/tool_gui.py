import cv2
import eel
import os, sys
from os.path import expanduser
import time
import numpy as np
from libdeda.pattern_handler import TDM, Pattern4
from libdeda.print_parser import *
from libdeda.privacy import AnonmaskApplier, AnonmaskApplierTdm, calibrationScan2Anonmask, \
    cleanScan


def main():
    eel.init(os.path.join(os.path.dirname(os.path.realpath(__file__)),'web'))

    #---
    #--- Extract and Decode section
    #---
    @eel.expose
    def forensic(uploads):
        file_uploads = []
        for upload in uploads:

            #upload is folder path:
            if os.path.isdir(upload):
                files = [os.path.join(upload, s) for s in os.listdir(upload)
                        if not os.path.isdir(os.path.join(upload, s))]
                file_count = 0
                for f in files:
                    filext = os.path.splitext(f)[1].lower()
                    filename = os.path.split(f)[1]
                    if(filext=='.jpeg' or filext=='.jpg' or filext=='.png' or filext=='.tiff' or filext=='.bmp'):
                        file_uploads.append(f)
                        file_count += 1
                if(file_count==0):
                    return ('%s không có ảnh hợp lệ.'%(upload))

            #upload is file path
            elif os.path.isfile(upload):
                filext = os.path.splitext(upload)[1].lower()
                filename = os.path.split(upload)[1]
                if(filext=='.jpeg' or filext=='.jpg' or filext=='.png' or filext=='.tiff' or filext=='.bmp'):
                    file_uploads.append(upload)
                else:
                    return '%s ảnh không hợp lệ. chỉ cho phép jpg, png, tiff hoặc bmp .'%(upload)
            else:
                return '%s đường dẫn không hợp lệ.'%(upload)

        # forensic analysis of uploads
        return forensicAction(file_uploads)


    def forensicAction(file_uploads):

        allresults = []
        fullfail = []
        extractfail = []
        errors = []

        for imgfile in file_uploads:
            fpath = os.path.split(imgfile)[1]
            imgresult = []
            try:
                with open(imgfile,"rb") as fp:
                    pp = PrintParser(fp.read())
            except YD_Parsing_Error as e: pattern = None
            else: pattern = pp.pattern
            if pattern is None:
                fullfail.append(fpath)
            elif pp.tdm is None:
                extractfail.append(fpath)
            else:
                #create table with yd matrix
                result_matrix = str(pp.tdm).split('\t')[0].split('\n')
                countdots = str(np.sum(pp.tdm.aligned==1))

                #create table with decoding results
                dec = pp.tdm.decode() # keys: manufacturer, raw, serial, timestamp

                result_decoding = []
                result_decoding.append(fpath)
                result_decoding.append(str(pp.pattern))

                if dec.get('manufacturer') != None:
                    result_decoding.append(dec.get('manufacturer'))
                else:
                    result_decoding.append('N/A')
                if dec.get('serial') != None:
                    result_decoding.append(dec.get('serial'))
                else:
                    result_decoding.append('N/A')
                if dec.get('timestamp') != None:
                    result_decoding.append(dec.get('timestamp').strftime("%Y-%m-%d %H:%M:%S"))
                else:
                    result_decoding.append('N/A')
                if dec.get('raw') != None:
                    result_decoding.append(dec.get('raw'))
                else:
                    result_decoding.append('N/A')
                result_decoding.append(countdots)

                imgresult.append(result_matrix)
                imgresult.append(result_decoding)
                allresults.append(imgresult)

        errors.append(fullfail)
        errors.append(extractfail)

        #expose failures
        if(len(file_uploads)>1 and (len(fullfail)>0 or len(extractfail)>0)):
            result = '%s Files: Trích xuất thành công.<br>'%(str(len(file_uploads)-len(fullfail)-len(extractfail)))
            if len(fullfail)>0:
                result = '%s %s Files: Không phát hiện được dấu chấm theo dõi.<br>'%(result, str(len(fullfail)))
            if len(extractfail)>0:
                result = '%s %s Files: Dấu chấm theo dõi được phát hiện, nhưng không thể trích xuất TDM hợp lệ.<br>'%(result, str(len(fullfail)))
            #send results to javascript
            eel.printForensicResult(allresults, errors)
            return result

        elif len(fullfail)>0:
            return 'Không có mẫu dấu chấm theo dõi nào được phát hiện.'
        elif len(extractfail)>0:
            return 'Không thể trích xuất.'

        #send results to javascript
        eel.printForensicResult(allresults, errors)
        return ''

    # #---
    # #--- Compare Documents
    # #---
    @eel.expose
    def compare(uploads):
        file_uploads = []
        for upload in uploads:

            #upload is folder path:
            if os.path.isdir(upload):
                files = [os.path.join(upload, s) for s in os.listdir(upload)
                        if not os.path.isdir(os.path.join(upload, s))]
                file_count = 0
                for f in files:
                    filext = os.path.splitext(f)[1].lower()
                    filename = os.path.split(f)[1]
                    if(filext=='.jpeg' or filext=='.jpg' or filext=='.png' or filext=='.tiff' or filext=='.bmp'):
                        file_uploads.append(f)
                        file_count += 1
                if(file_count==0):
                    return ('%s không chứa một hình ảnh hợp lệ.'%upload)

            #upload is file path:
            elif os.path.isfile(upload):
                filext = os.path.splitext(upload)[1].lower()
                filename = os.path.split(upload)[1]
                if(filext=='.jpeg' or filext=='.jpg' or filext=='.png' or filext=='.tiff' or filext=='.bmp'):
                    file_uploads.append(upload)
                else:
                    return ('%s không phải là một hình ảnh hợp lệ. Hiện tại chỉ cho phép jpg, png, tiff hoặc bmp.'%upload)
            else:
                return ('%s không hợp lệ Đường dẫn đến một hình ảnh hoặc một thư mục chứa chúng.'%upload)

        if len(file_uploads)<2:
            return 'Để so sánh các dấu chấm theo dõi, bạn phải nhập ít nhất 2 hình ảnh hoặc một thư mục chứa chúng.'

        #compare Image Uploads
        return compareAction(file_uploads)


    def compareAction(file_uploads):
        info = ""
        printers, errors, identical = comparePrints(file_uploads)

        if identical:
            info = 'Các điểm theo dõi của tất cả các hình ảnh đầu vào đã được phát hiện là giống nhau.'
        elif len(printers) == 1 and (len(file_uploads)-len(errors))==1:
            info =  'Chỉ có thể trích xuất các dấu chấm theo dõi của 1 trong số %s hình ảnh. Không thể so sánh.'%(str(len(file_uploads)))
        elif len(printers) == 1 and (len(file_uploads)-len(errors)) > 1:
            info =  '%s of %s hình ảnh đã được phân tích thành công và đã được phát hiện là giống nhau. <br>%s hình ảnh không có dấu chấm theo dõi hoặc không thể trích xuất.'%(str(len(file_uploads)-len(errors)), str(len(file_uploads)), str(len(errors)))
        elif len(errors) == 0:
            info = 'Các dấu chấm theo dõi của tất cả các hình ảnh đầu vào đã được phát hiện.<br>%s hình ảnh đã được trích xuất. <br>%s các mẫu khác nhau đã được tìm thấy.'%(str(len(file_uploads)), str(len(printers)))
        elif len(printers) == 0:
            info = 'Không phát hiện dấu chấm theo dõi.'
        else:
            info = 'Các dấu chấm theo dõi có thể được trích xuất trong %s trong %s ảnh. <br>%s các mẫu khác nhau đã được tìm thấy. <br>%s hình ảnh không có dấu chấm theo dõi hoặc không thể trích xuất.'%(str(len(file_uploads)-len(errors)), str(len(file_uploads)),str(len(printers)), str(len(errors)))

        results_compare = []

        for i, p in enumerate(printers):
            results_equal = []
            results_equal.append(str(i+1))
            results_equal.append(p['manufacturer'])
            fequals = []
            for f in p['files']:
                fequals.append(str(f))
            results_equal.append(fequals)
            results_compare.append(results_equal)

        if len(errors) > 0:
            results_error = []
            results_error.append('Errors')
            results_error.append('Những hình ảnh này không có dấu chấm theo dõi hoặc không thể trích xuất.')

            fequals = []
            for e, f in errors:
                fequals.append(str(f))
            results_error.append(fequals)
            results_compare.append(results_error)

        #send output to javascript
        eel.printCompareResult(info, results_compare)
        return ''

    #---
    #--- Anon Scan
    #---
    @eel.expose
    def anonScanAction(upload):
        if os.path.isfile(upload):
            filext = os.path.splitext(upload)[1].lower()
            path, filename = os.path.split(upload)
            path = '%s/'%path
            if(filext=='.jpeg' or filext=='.jpg' or filext=='.png' or filext=='.tiff' or filext=='.bmp'):
                ext = os.path.splitext(os.path.basename(upload))[1]
                with open(upload,"rb") as fpin:
                    outfile = cleanScan(fpin.read(),outformat=ext)

                output = '%s_anon%s'%(os.path.splitext(os.path.basename(upload))[0],ext)
                save = '%s%s'%(path,output)
                with open(save, "wb") as fpout:
                    fpout.write(outfile)
                info = 'Document anonymized and saved.'
                result = []
                result.append(path)
                result.append(filename)
                result.append(output)
                #send output to javascript
                eel.printAnonScan(info, result)
                return ''
            else:
                return 'không hợp lệ'
        else:
            return 'đường dẫn không hợp lệ'


    #---
    #--- Generate Print Mask
    #---
    @eel.expose
    def generateMask(upload):
        if os.path.isfile(upload):
            filext = os.path.splitext(upload)[1].lower()
            path = '%s/'%os.path.split(upload)[0]
            if(filext=='.jpeg' or filext=='.jpg' or filext=='.png' or filext=='.tiff' or filext=='.bmp'):
                try:
                    with open(upload,'rb') as fp:
                        mask = calibrationScan2Anonmask(fp.read(),copy=False)
                    output = '%smask.json'%path
                    with open(output,'wb') as fp:
                        fp.write(mask)
                    return 'Done. Mask was generated and saved as %smask.json'%path
                except:
                    return 'An Error'
            else:
                return 'không hợp lệ'
        else:
            return 'không phải đường dẫn hợp lệ'


    #---
    #--- Apply Print Mask
    #---
    @eel.expose
    def applyMask(page, mask, x, y, dotradius):
        if not os.path.isfile(page):
            return 'Đường dẫn không hợp lệ'
        if not os.path.isfile(mask): return 'không hợp lệ'
        pagename, pageext = os.path.splitext(page)
        pageext = pageext.lower()
        pagepath =  '%s/'%os.path.split(page)[0]
        maskext = os.path.splitext(mask)[1].lower()
        if not (pageext=='.pdf'):
            return ('File không hợp lệ '
                'Document.')
        if not (maskext=='.json'): return 'Not a valid Mask File (json).'
        try:
            if (x==''): x = None
            else: x = float(x)
            if (y==''): y = None
            else: y = float(y)
            if (dotradius==''): dotradius = 0.004
            else: dotradius = float(dotradius)

            with open(mask) as maskin:
                aa = AnonmaskApplier(maskin.read(),dotradius,x,y)

            with open('%s_masked.pdf'%pagename,'wb') as pdfout:
                with open(page, 'rb') as pdfin:
                    pdfout.write(aa.apply(pdfin.read()))

            xoff = aa.xOffset
            yoff = aa.yOffset
            dotrad = aa.dotRadius
            text_file = open('%scalibration_masked.txt'%pagepath, 'w')
            text_file.write('X-Offset: %s \ny-Offset: %s \nDotradius: %s'%(xoff, yoff, dotrad))
            text_file.close()
            info = 'Done. Masked document was generated and saved.'
            result = []
            result.append('%s_masked.pdf'%pagename)
            result.append('%scalibration_masked.txt'%pagepath)
            result.append(str(round(xoff,4)))
            result.append(str(round(yoff,4)))
            result.append(str(dotrad))

            #send output to javascript
            eel.printAnonMaskResult(info, result)
            return ''
        except:
            return 'An Error occoured.'

    #---
    #--- Apply Print Mask
    #---
    @eel.expose
    def generatePattern(pdf, datetime, serial, manufacturer, dotradius):
        if not os.path.isfile(pdf):
            return 'Đường dẫn không hợp lệ.'
        #date and time
        if(datetime==''):
            hour=11
            minutes=11
            day=11
            month=11
            year=18
        else:
            a = datetime.split(' ')
            date = a[0].split('.')
            time = a[1].split(':')
            hour = time[0]
            minutes = time[1]
            day = date[0]
            month = date[1]
            year = date[2]
        #serial number
        if(serial == ''):
            serial = 123456
        elif(len(serial) != 6):
            return 'Serial Number phải có 6 chữ số'
        else:
            try:
                serial = int(serial)
            except:
                return ('Serial Number phải có 6 chữ số')
        #manufacturer
        if(manufacturer == '' or manufacturer == '1'):
            manufacturer = 'Epson'
        elif(manufacturer == '2'):
            manufacturer = 'Xerox'
        elif(manufacturer == '3'):
            manufacturer = 'Dell'
        else:
            return ('Manufacturer phải là Xerox, Epson hoặc Dell')
        #dotRadius
        if(dotradius == ''):
            dotradius = 0.004
        else:
            dotradius = float(dotradius)

        tdm = TDM(Pattern4, content=dict(
            serial=serial,
            hour=hour,
            minutes=minutes,
            day=day,
            month=month,
            year=year,
            manufacturer=manufacturer,
        ))
        home = expanduser('~')
        OUTFILE = '%s/new_dots.pdf'%home
        aa = AnonmaskApplierTdm(tdm,dotRadius=dotradius)
        with open(OUTFILE,'wb') as pdfout:
            with open(pdf,"rb") as pdfin:
                pdfout.write(aa.apply(pdfin.read()))

        #create table with yd matrix
        result_matrix = str(tdm).split('\t')[0].split('\n')
        countdots = str(np.sum(tdm.aligned==1))
        #result matrix
        timestamp = ('%s.%s.%s %s:%s'%(str(day), str(month),str(year),str(hour),str(minutes)))
        result_decoding = [OUTFILE, 'Pattern 4', manufacturer, str(serial), timestamp, dotradius,countdots]
        #send output to javascript
        eel.printCreateResult(result_matrix, result_decoding)
        return ''

    #---
    #--- Start GUI
    #---
    # options: see https://github.com/samuelhwilliams/Eel#app-options
    # mode: #"chrome", #or "chrome-app"
    # chromeFlags: ["--size=(1024, 800)"]

    eel.start('index.html',  mode='', port=8080)


if __name__ == '__main__':
    main()
