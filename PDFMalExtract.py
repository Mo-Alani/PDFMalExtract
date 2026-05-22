'''
*****************************

PDFMalExtract v0.1
Author: Mohammed M. Alani
https://github.com/Mo-Alani/

*****************************
'''
import sys
import hashlib
import pymupdf
from pymupdf import TextPage
import os
import pandas as pd
import argparse
from tqdm import tqdm

# This function calculates the SHA256 hash of the PDF file.
def sha256hash(file_name):
        BUF_SIZE = 65536  # The buffer size can be set to any number
        sha256 = hashlib.sha256()
        with open(file_name, 'rb') as f:
                while True:
                        data = f.read(BUF_SIZE)
                        if not data:
                                break
                        sha256.update(data)
        return sha256.hexdigest()

# Parsing the arguments
parser = argparse.ArgumentParser(description="PDFMalExtract is tool used to extract static features from PDF files for malware detection.")
parser.add_argument("-i", "--input", metavar="input-folder",type=str, help="Input folder that contains the PDF files. This can be absolute or relative path")
parser.add_argument("-o","--output", metavar="output-file",type=str,help="CSV output file name. Default is output.csv",default="output.csv")
parser.add_argument("-l","--label",metavar="output-label",type=str,help="Label to be added to all rows. Default is empty.", default="")
args = parser.parse_args()

# If there is no input folder given, the script will print its help page and exit
if (not args.input):
        parser.print_help()
        sys.exit()

# Reading the input folder. If it is not an absolute path, it is made into an absolute path
dir = os.getcwd()
path = args.input
if(not os.path.isabs(path)):
         path = os.path.join(dir,path)
if(not os.path.isdir(path)):
        print("The path you provided for the PDF files is not a valid folder")
        sys.exit()

# Preparing the dataframe to be used to hold the extracted data, with feature names
res = pd.DataFrame(columns=('hash','pdfsize','metadata size', 'pages','xref length','title length','isEncrypted','embedded files','images','contains_text','pdf_ver','obj','endobj','stream','endstream','trailer', 'xref', 'startxref','page_command', 'Encrypt', 'ObjStm','JS','JavaScript','AA','OpenAction','Acroform','JBIG2Decode', 'RichMedia','Launch','EmbeddedFile','XFA', 'Colors','URI','BaseEncoding','Encoding','ProcSet','Registry','Resources','www','server','Root','BitsPerComponent','Label')) 

# This line prevents certain warnings from appearing in the middle of processing of certain partially corrupted PDFs or some PDFs that are not abiding by the rules. The errors that cause an exception will still be visible.
# Take a look here for a bit more information https://github.com/pymupdf/pymupdf/issues/4719
# Feel free to comment it out if you want to see the warnings and errors.
pymupdf.TOOLS.mupdf_display_errors(False)

i = 0
#Printing the number of files found in the given folder
no_files = len(os.listdir(path))
print(f"{no_files} file(s) found in the folder {path}")

print("Processing the files...")

# Fetching the label and the output file name from the arguments
the_label=args.label
the_output=args.output

# Looping through the files one by one to extract the features and create the dataset records
# Using tqdm just to give you a hint on how long this is going to take and how is it progressing. If you dont like it, just remove the tqdm(     ) and keep only os.listdire(path)
for file_name in tqdm(os.listdir(path)):
        f = path + "/" + file_name
        #print(f)
        try:
                doc = pymupdf.open(f)
        except:
                #skip the file because it is corrupted
                continue
        # Loading the metadata
        try:
                metadata = doc.metadata
        except:
                try:
                        doc.scrub(garbage=4)
                        metadata = doc.metadata
                except:
                        print(f"File {f} is too corrupted to extract the metadata")
                        continue
        
        if metadata:
                #Finding the PDF version in the header
                pdf_ver = float(metadata['format'][4:7])
                
                #finding if the the file is Encrypted from the metadata
                try:
                        isEncrypted = metadata['encryption']
                        if(not isEncrypted):
                                isEncrypted = 0
                        else:
                                isEncrypted = 1
                except:
                        print(f"File {f} is too corrupted to find encryption status")
                # Finding the file title if it is set in the metadata
                if(not metadata['title']):
                        title = ''
                else:
                        try:
                                title = metadata['title']
                        except:
                                #doc.scrub(garbage=4)
                                #title = metadata['title']
                                print(f"File {f} title is too corrupted to be captured")

        else:
                #skip the file because it is corrupted and metadata cannot be extracted
                continue
       
        #number of objects
        try:
                objects = doc.xref_length()
        except:
                try:
                        doc.scrub(garbage=4)
                        objects = doc.xref_length()
                except:
                        print(f"File {f} is too corrupted")
        # Finding number of pages in pdf file
        try:
                numPages = doc.page_count
        except:
                try:
                        doc.scrub(garbage=4)
                        numPages = doc.page_count
                except:
                        print(f"file {f} too corrupted")
                # If a PDF file throws after the scrub, it means that the file is corrupted

        # Getting pdf file size in kilobytes
        pdfsize = int(os.path.getsize(f)/1000)

        # Finding extracted text. If the text is less than 50 characters, it is considered empty
        # This is a number I chose. You can pick a different threshold, or make it 1
        # If there was no text or text less than 50 characters found, the text_found will return -1
        found = 0
        text = ""
        try:
                for page_index in range(len(doc)):
                        try:
                                text += doc[page_index].get_text()
                                if (len(text) > 50):
                                        found = 1
                                        break
                        except:
                                pass
                # Number of files embedded in a pdf
                embedcount = doc.embfile_count()
        except:
                found = -1
                embedcount = 0
                 
        #number of images by cycling through all pages and fetching the number of images
        imgcount = 0
        try:
                for page_index in range(len(doc)):
                        page = doc[page_index]
                        image_list = page.get_images()
                        imgcount += len(image_list)
                        
        except:
                imgcount = -1
        # Looking for specific strings within the PDF file
        with open(f,'rb') as the_file:
                bin_data = the_file.read()
                endobj_c = bin_data.count(b'endobj')
                obj_c = bin_data.count(b'obj') - endobj_c
                endstream_c = bin_data.count(b'endstream')
                stream_c = bin_data.count(b'stream') - endstream_c
                trailer_c = bin_data.count(b'trailer')
                startxref_c = bin_data.count(b'startxref')
                xref_c = bin_data.count(b'xref') - startxref_c
                page_c = bin_data.count(b'/Page') - bin_data.count(b'/Pages')
                encrypt_c = bin_data.count(b'/Encrypt')
                objstm_c = bin_data.count(b'/ObjStm')
                js_c = bin_data.count(b'/JS')
                javascript_c = bin_data.count(b'/JavaScript')
                aa_c = bin_data.count(b'/AA')
                openaction_c = bin_data.count(b'/OpenAction')
                acroform_c = bin_data.count(b'/Acroform')
                jbig_c = bin_data.count(b'/JBIG2Decode')
                richmedia_c = bin_data.count(b'/RichMedia')
                launch_c = bin_data.count(b'/Launch')
                embeddedfile_c = bin_data.count(b'/EmbeddedFile')
                xfa_c = bin_data.count(b'/XFA')
                colors_c = bin_data.count(b'/Colors > 2^24')
                uri_c = bin_data.count(b'/URI')
                baseencoding_c = bin_data.count(b'j/BaseEncoding')
                encoding_c = bin_data.count(b'/Encoding')
                procset_c = bin_data.count(b'/ProcSet')
                registry_c = bin_data.count(b'/Registry')
                resources_c = bin_data.count(b'/Resources')
                www_c = bin_data.count(b'/www')
                server_c = bin_data.count(b'/server')
                root_c = bin_data.count(b'/Root')
                bits_c = bin_data.count(b'/BitsPerComponent')

        #writing the features into the dataframe
        res.loc[i] = [sha256hash(f)] + [pdfsize] + [len(str(metadata).encode('utf-8'))] + [numPages] + [objects] + [len(title)] + [isEncrypted] + [embedcount] + [imgcount] + [found] + [pdf_ver]+ [obj_c] +[endobj_c]+[stream_c]+[endstream_c]+[trailer_c]+[xref_c]+[startxref_c]+[page_c]+[encrypt_c]+[objstm_c]+[js_c]+[javascript_c]+[aa_c]+[openaction_c]+[acroform_c]+[jbig_c]+[richmedia_c]+[launch_c]+[embeddedfile_c]+[xfa_c]+[colors_c]+[uri_c]+[baseencoding_c]+[encoding_c]+[procset_c]+[registry_c]+[resources_c]+[www_c]+[server_c]+[root_c]+[bits_c]+[the_label]
        i +=1
                
res.to_csv(os.path.relpath(the_output,start=os.curdir),index=False)
print(f"All features extracted successfully from {i} files, and saved to {the_output}...")
if i < no_files:
        print(f"{no_files-i} files were skipped because they were corrupted.")