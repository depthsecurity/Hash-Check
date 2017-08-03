#!/usr/bin/python
import base64
import hashlib
from Crypto.Hash import SHA, HMAC, MD4, SHA224, SHA256, SHA384, SHA512
import passlib.hash #sql, nt, md5_crypt

def writeHash(password, salt):
	hashes = {}
	hashes[password] = "Plain-text"
	hashes[password.encode("hex")] = "Hex"
	hashes[base64.b16encode(password)] = "Base16"
	hashes[base64.b32encode(password)] = "Base32"
	hashes[base64.b64encode(password)] = "Base64"
	hashes[base64.b64encode(salt+":"+password)] = "Basic Auth"
	hashes[base64.b64encode(hashlib.md5(password).digest())] =  "md5"
	hashes[base64.b64encode(hashlib.md5(password+salt).digest())] =  "md5+salt"
	hashes[base64.b64encode(hashlib.md5(salt+password).digest())] =  "salt+md5"
	hashes[base64.b64encode(HMAC.new(password,salt,SHA).digest())] =  "hmac-sha1; key=password"
	hashes[base64.b64encode(HMAC.new(salt,password,SHA).digest())] =  "hmac-sha1; key=salt"
	hashes[base64.b64encode(HMAC.new(password,salt,SHA256).digest())] = "hmac-sha256; key=password"
	hashes[base64.b64encode(HMAC.new(salt,password,SHA256).digest())] =  "hmac-sha256; key=salt"
	hashes[base64.b64encode(HMAC.new(password,salt,SHA512).digest())] =  "hmac-sha512; key=password"
	hashes[base64.b64encode(HMAC.new(salt,password,SHA512).digest())] =  "hmac-sha512; key=salt"
	hashes[base64.b64encode(hashlib.sha1(password).digest())] =  "sha1"
	hashes[base64.b64encode(hashlib.sha224(password).digest())] = "sha224"
	hashes[base64.b64encode(hashlib.sha256(password).digest())] = "sha256"
	hashes[base64.b64encode(hashlib.sha512(password).digest())] = "sha512"
	hashes[base64.b64encode(hashlib.sha1(password+salt).digest())] =  "sha1+salt"
	hashes[base64.b64encode(hashlib.sha224(password+salt).digest())] =  "sha224+salt"
	hashes[base64.b64encode(hashlib.sha256(password+salt).digest())] = "sha256+salt"
	hashes[base64.b64encode(hashlib.sha512(password+salt).digest())] = "sha512+salt"
	hashes[base64.b64encode(hashlib.sha1(salt+password).digest())] = "salt+sha1"
	hashes[base64.b64encode(hashlib.sha224(salt+password).digest())] = "salt+sha224"
	hashes[base64.b64encode(hashlib.sha256(salt+password).digest())] = "salt+sha256"
	hashes[base64.b64encode(hashlib.sha512(salt+password).digest())] = "salt+sha512"
	hashes[base64.b64encode(MD4.new(password).digest())] = "md4"		
	hashes[hashlib.md5(password).hexdigest()] = "md5"
	hashes[hashlib.md5(password+salt).hexdigest()] = "md5+salt"
	hashes[hashlib.md5(salt+password).hexdigest()] = "salt+md5"
	hashes[HMAC.new(password,salt,SHA).hexdigest()] = "hmac-sha1; key=password"
	hashes[HMAC.new(salt,password,SHA).hexdigest()] = "hmac-sha1; key=salt"
	hashes[HMAC.new(password,salt,SHA256).hexdigest()] = "hmac-sha256; key=password"
	hashes[HMAC.new(salt,password,SHA256).hexdigest()] = "hmac-sha256; key=salt"
	hashes[HMAC.new(password,salt,SHA512).hexdigest()] = "hmac-sha512; key=password"
	hashes[HMAC.new(salt,password,SHA512).hexdigest()] = "hmac-sha512; key=salt"
	hashes[hashlib.sha1(password).hexdigest()] = "sha1"
	hashes[hashlib.sha224(password).hexdigest()] = "sha224"
	hashes[hashlib.sha384(password).hexdigest()] = "sha256"
	hashes[hashlib.sha512(password).hexdigest()] = "sha512"
	hashes[hashlib.sha1(password+salt).hexdigest()] = "sha1+salt"
	hashes[hashlib.sha224(password+salt).hexdigest()] = "sha224+salt"
	hashes[hashlib.sha256(password+salt).hexdigest()] = "sha256+salt"
	hashes[hashlib.sha512(password+salt).hexdigest()] = "sha512+salt"
	hashes[hashlib.sha1(salt+password).hexdigest()] = "salt+sha1"
	hashes[hashlib.sha224(salt+password).hexdigest()] = "salt+sha224"
	hashes[hashlib.sha256(salt+password).hexdigest()] = "salt+sha256"
	hashes[hashlib.sha512(salt+password).hexdigest()] = "salt+sha512"
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