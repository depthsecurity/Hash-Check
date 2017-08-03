# Hash-Check
## Introduction
passwordHashScanner.py is a custom Burp extension written in Python to check requests and responses for potential password hashes. hashMaker.py is a "helper" script to generate a file that contains different hashing algorithms and encodings. The generated file will be used by passwordHashScanner.py

## Usage
hashMaker.py is a "helper" script used to generate a file that contains colon-separated hash and hashtype values. When the script is run, prompts will be displayed for the password, salt (I tytpically use my username), and output file name which defaults to hashout.txt if it is not changed. As an example, md4 hash of "hashcat" would appear as r+BIZ+x6OEUUVXmpX3Lspw==:md4 in the file.

passwordHashScanner.py is the actual Burp extension. When the exension is loaded, a new suite tab called Hash Check will be added to Burp. From the Hash Check suite tab, you can import your hashes by clicking the "Open hashout.txt" button, selecting your file, and clicking the "Parse hash file" button. After parsing the hashes, the "Output" text area will display the imported hashes. If a potential hash match is discovered, a new scan issue will be created to notify you of the hash, hash type, and the page it was discovered on.

## Requirements
### passwordHashScanner.py
* Burpsuite

### hashMaker.py
These requirements should already be met on in Kali
* hashlib
* pycrypto
* passlib

