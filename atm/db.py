from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

import binascii
import requests
import json
import re

class db:

    URL = "http://127.0.0.1:5000"

    key_pair = RSA.generate(2048)
    public_key = key_pair.publickey()
    foreign_key = ""
    secureToken = ""
    user = ""

    def __init__(self):
        print("Initialized")

    #Login Method
    def login(self, cardnum, password):
        #Start connection by sending Public Key
        #JSON Package, URL Created and Posted
        package = {
            'public_key': db.getStringFromBytes(str(binascii.hexlify(self.public_key.export_key('DER'))))
        }
        address = self.URL + "/start"
        response = requests.post(address, json=package) 

        #Import Foreign Key and Secure Token
        cipher = PKCS1_OAEP.new(self.key_pair)
        self.foreign_key = RSA.import_key(binascii.unhexlify(response.json()['public_key']))
        self.secureToken = db.getStringFromBytes(str(cipher.decrypt(binascii.unhexlify(response.json()['secure_token']))))

        package = {
            'cardnum': cardnum,
            'password': password
        }
        package = db.encrpytPackage(self.foreign_key, package, self.secureToken)
        address = self.URL + "/login"
        response = requests.post(address, json=package)
        self.user = db.decrpytPackage(self.key_pair, response.json())
        if(self.user['status'] == "s"):
            return True
        else:
            return False

    #Modify Balance Method
    def modbal(self, amount, description):
        package = db.encrpytPackage(self.foreign_key, {
            'amount': amount,
            'description': description
        }, self.secureToken)
        address = self.URL + "/modbal"
        response = requests.post(address, json=package)
        package = db.decrpytPackage(self.key_pair, response.json())
        if(package['status'] == "s"):
            self.user['balance'] = package['balance']
        return package

    #Get Bill
    def bill(self, authority):
        package = db.encrpytPackage(self.foreign_key, {
            'authority': authority
        }, self.secureToken)
        address = self.URL + "/bill"
        response = requests.post(address, json=package)
        package = db.decrpytPackage(self.key_pair, response.json())
        return package

    #Change Pin
    def changepin(self, old_pin, new_pin):
        package = db.encrpytPackage(self.foreign_key, {
            'old_pin': old_pin,
            'new_pin': new_pin
        }, self.secureToken)
        address = self.URL + "/changepin"
        response = requests.post(address, json=package)
        package = db.decrpytPackage(self.key_pair, response.json())
        return package

    #Get Transactions
    def transactions(self):
        package = db.encrpytPackage(self.foreign_key, {}, self.secureToken)
        address = self.URL + "/transactions"
        response = requests.post(address, json=package)
        package = db.decrpytPackage(self.key_pair, response.json())
        return package

    #Change 2 Factor Authentication
    def change2Fac(self, code):
        package = db.encrpytPackage(self.foreign_key, {
            '2fac_code': code
        }, self.secureToken)
        address = self.URL + "/twoFA/update"
        response = requests.post(address, json=package)
        package = db.decrpytPackage(self.key_pair, response.json())
        if(package['status'] == "s"):
            self.user['2fac_code'] = code
        return package

    #Exit
    def deauth(self):
        package = db.encrpytPackage(self.foreign_key, {}, self.secureToken)
        address = self.URL + "/deauth"
        response = requests.post(address, json=package)
        package = response.json()

        self.key_pair = RSA.generate(2048)
        self.public_key = self.key_pair.publickey()
        self.foreign_key = ""
        self.secureToken = ""
        self.user = ""

        return package

    #Get String Characters from Hex Bytes
    @staticmethod
    def getStringFromBytes(text):
        return re.search("b'(.*)'", text).group(1)

    #Encrypt JSON Package
    @staticmethod
    def encrpytPackage(key, package, secureToken):
        cipher = PKCS1_OAEP.new(key)
        encrypted_package = {}
        for (k, v) in package.items():
            encrypted_package[k] = db.getStringFromBytes(str(binascii.hexlify(cipher.encrypt(v.encode('utf-8')))))
        encrypted_package['secure_token'] = secureToken
        return encrypted_package

    #Decrypt JSON Package
    @staticmethod
    def decrpytPackage(key, package):
        cipher = PKCS1_OAEP.new(key)
        decrypted_package = {}
        for (k, v) in package.items():
            decrypted_package[k] = db.getStringFromBytes(str(cipher.decrypt(binascii.unhexlify(v))))
        return decrypted_package

    #Ping Server
    def ping(self):
        try:
            status = requests.get(self.URL + "/")
        except:
            return False
        else:
            return status.status_code == 200
            