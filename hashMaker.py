#!/usr/bin/python
#Written by: Brian Berg - www.github.com/xexzy
import base64
import urllib
from Crypto.Hash import SHA, HMAC, MD4, MD5, SHA224, SHA256, SHA384, SHA512
import passlib.hash #sql, nt, md5_crypt

def writeHash(password, salt):
	hashes = {}
	hashes[password] = "Plain-text"
	hashes[urllib.quote(password, safe='')] = "URL Encoded"
	hashes[password.encode("hex")] = "Hex"
	hashes[base64.b16encode(password)] = "Base16"
	hashes[base64.b32encode(password)] = "Base32"
	hashes[base64.b64encode(password)] = "Base64"
	hashes[base64.b64encode(salt+":"+password)] = "Basic Auth"
	hashes[base64.b64encode(MD5.new(password).digest())] =  "md5"
	hashes[base64.b64encode(MD5.new(password+salt).digest())] =  "md5+salt"
	hashes[base64.b64encode(MD5.new(salt+password).digest())] =  "salt+md5"
	hashes[base64.b64encode(HMAC.new(password,salt,SHA).digest())] =  "hmac-sha1; key=password"
	hashes[base64.b64encode(HMAC.new(salt,password,SHA).digest())] =  "hmac-sha1; key=salt"
	hashes[base64.b64encode(HMAC.new(password,salt,SHA256).digest())] = "hmac-sha256; key=password"
	hashes[base64.b64encode(HMAC.new(salt,password,SHA256).digest())] =  "hmac-sha256; key=salt"
	hashes[base64.b64encode(HMAC.new(password,salt,SHA512).digest())] =  "hmac-sha512; key=password"
	hashes[base64.b64encode(HMAC.new(salt,password,SHA512).digest())] =  "hmac-sha512; key=salt"
	hashes[base64.b64encode(SHA.new(password).digest())] =  "sha1"
	hashes[base64.b64encode(SHA224.new(password).digest())] = "sha224"
	hashes[base64.b64encode(SHA256.new(password).digest())] = "sha256"
	hashes[base64.b64encode(SHA512.new(password).digest())] = "sha512"
	hashes[base64.b64encode(SHA.new(password+salt).digest())] =  "sha1+salt"
	hashes[base64.b64encode(SHA224.new(password+salt).digest())] =  "sha224+salt"
	hashes[base64.b64encode(SHA256.new(password+salt).digest())] = "sha256+salt"
	hashes[base64.b64encode(SHA512.new(password+salt).digest())] = "sha512+salt"
	hashes[base64.b64encode(SHA.new(salt+password).digest())] = "salt+sha1"
	hashes[base64.b64encode(SHA224.new(salt+password).digest())] = "salt+sha224"
	hashes[base64.b64encode(SHA256.new(salt+password).digest())] = "salt+sha256"
	hashes[base64.b64encode(SHA512.new(salt+password).digest())] = "salt+sha512"
	hashes[base64.b64encode(MD4.new(password).digest())] = "md4"		
	hashes[MD5.new(password).hexdigest()] = "md5"
	hashes[MD5.new(password+salt).hexdigest()] = "md5+salt"
	hashes[MD5.new(salt+password).hexdigest()] = "salt+md5"
	hashes[HMAC.new(password,salt,SHA).hexdigest()] = "hmac-sha1; key=password"
	hashes[HMAC.new(salt,password,SHA).hexdigest()] = "hmac-sha1; key=salt"
	hashes[HMAC.new(password,salt,SHA256).hexdigest()] = "hmac-sha256; key=password"
	hashes[HMAC.new(salt,password,SHA256).hexdigest()] = "hmac-sha256; key=salt"
	hashes[HMAC.new(password,salt,SHA512).hexdigest()] = "hmac-sha512; key=password"
	hashes[HMAC.new(salt,password,SHA512).hexdigest()] = "hmac-sha512; key=salt"
	hashes[SHA.new(password).hexdigest()] = "sha1"
	hashes[SHA224.new(password).hexdigest()] = "sha224"
	hashes[SHA256.new(password).hexdigest()] = "sha256"
	hashes[SHA512.new(password).hexdigest()] = "sha512"
	hashes[SHA.new(password+salt).hexdigest()] = "sha1+salt"
	hashes[SHA224.new(password+salt).hexdigest()] = "sha224+salt"
	hashes[SHA256.new(password+salt).hexdigest()] = "sha256+salt"
	hashes[SHA512.new(password+salt).hexdigest()] = "sha512+salt"
	hashes[SHA.new(salt+password).hexdigest()] = "salt+sha1"
	hashes[SHA224.new(salt+password).hexdigest()] = "salt+sha224"
	hashes[SHA256.new(salt+password).hexdigest()] = "salt+sha256"
	hashes[SHA512.new(salt+password).hexdigest()] = "salt+sha512"
	hashes[MD4.new(password).hexdigest()] = "md4"
	hashes[passlib.hash.mysql323.hash(password)] = "mysql323"
	hashes[passlib.hash.mysql41.hash(password)] = "mysql41"
	hashes[passlib.hash.mssql2005.hash(password).split("x")[1]] = "mssql2005"
	hashes[passlib.hash.mssql2000.hash(password).split("x")[1]] = "mssql2000"
	hashes[passlib.hash.md5_crypt.hash(password)] = "md5crypt (unix)"
	hashes[passlib.hash.nthash.hash(password)] = "nt"
	return hashes

def writeFile(hashes, outfile):
	with open(outfile,"w") as hashout:
		for hashword in hashes.keys():
			hashout.write(hashword+":"+hashes[hashword]+"\n")
	return
			
if __name__ == '__main__':
	password = raw_input("Enter your password: ")
	salt = raw_input("Enter salt: ")
	outfile = raw_input("Enter output file name:[hashout.txt] ")
	if outfile == "":
		outfile = "hashout.txt"
	hashes = writeHash(password,salt)
	writeFile(hashes, outfile)
