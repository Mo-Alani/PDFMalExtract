# PDFMalExtract
Feature extraction from PDF files for malware detection purposes. Current version 0.1.
***
## *Overview*
PDFMalExtract is a python script that extracts 41 features from PDF files that can help in detecting PDF-based malware. The features extracted were chosen based on thorough analysis of about 12k malicious PDF files obtained from different sources. The goal is to produce a dataset (in CSV format) that can be used to train and test machine learning-based malware detection systems. The complete script is in the file ``PDFMalExtract.py``.

The script was inspired by [PDFMalLyzer](https://github.com/ahlashkari/PDFMalLyzer), and started as a hard fork from it, but ended up being a full re-write, with major expansion in the features extracted and techniques used in the extraction.

Feel free to email me at ``m (at) alani.me`` if you have any questions, or if you wish to contribute to the project.

## *Requirements*
This script requires the following packages:
* ``pyMuPDF``
* ``pandas``
* ``tqdm``

The script was tested with pyMuPDF version 1.26.7, and Python v3.11 on a Linux machine. If you want to run the code on Windows, you'll need to replace all the ``/`` with ``\`` in the code.

## *How to use it*
Download this repository using 
```bash
git clone https://github.com/Mo-Alani/PDFMalExtract.git
```

You can ``pip install -r requirements.txt`` that's in the main folder of the project, if needed.

You need to place all of your PDF files in a single folder, and then run 
```bash
python PDFMalExtractor.py -i input-folder -o output-file -l label
```
Where,

``input-folder`` is the name of the folder that contains your PDF file. The path can be relative or absolute.

``output-file`` is the name of CSV file where the extracted features should be saved. The default is output.csv

``label`` is the label to assign to the records in the dataset. The default is empty.

Depending on how you're labeling the dataset, you could label the benign PDFs 0, and the malicious ones 1, or you could use more elaborate labeling by the malware type or family name.

## *Extracted features*

| **Feature Name**     | **Description**                                                                                                                                                     |
|----------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **hash**             | The SHA256 hashof the PDF file. This should be removed before training the classifier. It was kept only to help detect duplications in the pdf files.               |
| **pdfsize**          | Size of the PDF file in kilobytes.                                                                                                                                  |
| **metadata size**    | Size of metadata extracted from the PDF file, in bytes.                                                                                                             |
| **pages**            | Number of pages in the PDF file.                                                                                                                                    |
| **xref length**      | xref length as extracted from the file header.                                                                                                                      |
| **title length**     | Number of characters in the file title.                                                                                                                             |
| **isEncrypted**      | 1 If the file is encrypted, and 0 otherwise.                                                                                                                        |
| **embedded files**   | Number of embedded files inside the PDF as extracted from the PDF header                                                                                             |
| **images**           | Number of images in the PDF file. This will return -1 if the file is corrupted and doesn't show the number of images.                                                                                                                                  |
| **contains_text**    | Does the file contain a certain number of characters of text? (the default threshold is 50 characters). This shows 1, is the threshold is met, 0 if it wasn't met, and -1 if the file is corrupted and the script couldn't read the text. |
| **pdf_ver**          | Version of the PDF file, as extracted fro mthe file header.                                                                                                         |
| **obj**              | Number of occurrences of the string "obj" in the PDF file.                                                                                                          |
| **endobj**           | Number of occurrences of the string "endobj" in the PDF file.                                                                                                       |
| **stream**           | Number of occurrences of the string "stream" in the PDF file.                                                                                                       |
| **endstream**        | Number of occurrences of the string "endstream" in the PDF file.                                                                                                    |
| **trailer**          | Number of occurrences of the string "trailer" in the PDF file.                                                                                                      |
| **xref**             | Number of occurrences of the string "xref" in the PDF file.                                                                                                         |
| **startxref**        | Number of occurrences of the string "startxref" in the PDF file.                                                                                                    |
| **page_command**     | Number of occurrences of the string "/Page" in the PDF file.                                                                                                        |
| **Encrypt**          | Number of occurrences of the string "/Encrypt" in the PDF file.                                                                                                     |
| **ObjStm**           | Number of occurrences of the string "/ObJStm" in the PDF file.                                                                                                      |
| **JS**               | Number of occurrences of the string "/JS" in the PDF file.                                                                                                          |
| **JavaScript**       | Number of occurrences of the string "/JavaScript" in the PDF file.                                                                                                  |
| **AA**               | Number of occurrences of the string "/AA" in the PDF file.                                                                                                          |
| **OpenAction**       | Number of occurrences of the string "/OpenAction" in the PDF file.                                                                                                  |
| **Acroform**         | Number of occurrences of the string "/Acroform" in the PDF file.                                                                                                    |
| **JBIG2Decode**      | Number of occurrences of the string "/JBIG2Decode" in the PDF file.                                                                                                 |
| **RichMedia**        | Number of occurrences of the string "/RichMedia" in the PDF file.                                                                                                   |
| **Launch**           | Number of occurrences of the string "/Launch" in the PDF file.                                                                                                      |
| **EmbeddedFile**     | Number of occurrences of the string "/EmbeddedFile" in the PDF file.                                                                                                |
| **XFA**              | Number of occurrences of the string "/XFA" in the PDF file.                                                                                                         |
| **Colors**           | Number of occurrences of the string "/Colors > 2^24" in the PDF file.                                                                                               |
| **URI**              | Number of occurrences of the string "/URI" in the PDF file.                                                                                                         |
| **BaseEncoding**     | Number of occurrences of the string "/BaseEncoding" in the PDF file.                                                                                                |
| **Encoding**         | Number of occurrences of the string "/Encoding" in the PDF file.                                                                                                    |
| **ProcSet**          | Number of occurrences of the string "/ProcSet" in the PDF file.                                                                                                     |
| **Registry**         | Number of occurrences of the string "/Registry" in the PDF file.                                                                                                    |
| **Resources**        | Number of occurrences of the string "/Resources" in the PDF file.                                                                                                   |
| **www**              | Number of occurrences of the string "/www" in the PDF file.                                                                                                         |
| **server**           | Number of occurrences of the string "/server" in the PDF file.                                                                                                      |
| **Root**             | Number of occurrences of the string "/Root" in the PDF file.                                                                                                        |
| **BitsPerComponent** | Number of occurrences of the string "/BitsPerComponent" in the PDF file.                                                                                            |
| **Label**            | The label of the entry                                                                                                                                              |

If you think that there are other features that can help the detection process, please reach out via email and I'll see if I can include the proposed feature in the next version.

## *Acknowledgements*
This script was built as part of a research project funded by [Rochester Instituite of Technology - Dubai](https://www.rit.edu/dubai/), with grant number RITD-ARC-2025-001.

## *Contributors*
* **Mohammed M. Alani** ([@Mo-Alani](https://github.com/Mo-Alani/))