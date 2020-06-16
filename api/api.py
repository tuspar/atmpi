import flask #API Setup 
from flask import request, jsonify #JSON Packager & Package Reader

from Crypto.PublicKey import RSA #RSA KeyGen
from Crypto.Cipher import PKCS1_OAEP #Cipher Enryption RSA
from Crypto.Hash import SHA256 #SHA256 Hashing

import binascii #Hex Encoding
import re #Character Extraction
import mysql.connector #MySQL Interface
import random, string #Standard Python Libraries
from time import gmtime #GMT Time 
import time #Time Formatting

app = flask.Flask(__name__)
#app.config["DEBUG"] = True

#Setup Connection
mydb = mysql.connector.connect(
    host = 'localhost',
    user = 'root',
    passwd = 'root'
)
mycursor = mydb.cursor(buffered=True)

@app.route('/', methods=['GET'])
def home():
    return "<h1>ATM DB Backend API</h1><p>This is a prototype</p>"

@app.route('/start', methods=['GET', 'POST'])
def api_start():
    #Create Public, Private and Foreign Key
    key_pair = RSA.generate(2048)
    public_key = key_pair.publickey()
    foreign_key_str = str(request.get_json()['public_key'])

    # Generates 16 character alpha-numeric code
    secureToken = ''.join(random.choice(string.ascii_uppercase          
        + string.ascii_lowercase + string.digits) for _ in range(16)) 

    #Adds Public Key, Private Key, Foreign Key and Secure Token to Database
    mycursor.execute("INSERT INTO mydb.sessions (public_key, private_key, foreign_key, securetoken, auth) VALUES ('" + 
    getStringFromBytes(str(binascii.hexlify(public_key.export_key('DER')))) + "', '" +
    getStringFromBytes(str(binascii.hexlify(key_pair.export_key('DER')))) + "', '" +
    foreign_key_str + "', '" +
    secureToken + "', '" +
    "0" + "')")
    mydb.commit()

    #Returns Public Key and Encrypted Secure Token
    return jsonify({
        'public_key': getStringFromBytes(str(binascii.hexlify(public_key.export_key('DER')))),
        'secure_token': encrypt(foreign_key_str, secureToken)
    })

@app.route('/login', methods=['GET', 'POST'])
def api_login():
    #Decrpyt Package and get Card number and Password
    package = decrpytPackage(request.get_json())
    cardnum = package['cardnum']
    password = package['password']
    secure_token = package['secure_token']

    #Hash Password
    hash_object = SHA256.new(data=password.encode('utf-8'))
    hashed_password = hash_object.hexdigest()

    #Compare Card Number and Hashed Pin with table
    mycursor.execute("SELECT * FROM mydb.users WHERE cardnum = '" + cardnum + "' AND account_pin = '" + hashed_password + "'")
    rowcount = mycursor.rowcount
    result = mycursor.fetchone()

    #Check if the row exists and the account is not locked
    if(rowcount == 1 and result[6] != "3"):
        #Creates a user JSON object
        package = {
            'status': 's',
            'cardnum': cardnum,
            'first_name': result[1],
            'last_name': result[2],
            'type': result[4],
            'balance': result[5],
            'lock': '0',
            '2fa_code': result[7]
        }

        #Gives token authorization and resets the lock
        mycursor.execute("UPDATE mydb.sessions SET auth = '1', usercardnum = '" + cardnum + "' WHERE securetoken = '" + secure_token + "'")
        mycursor.execute("UPDATE mydb.users SET `lock` = '0' WHERE cardnum = '" + cardnum + "'")
        mydb.commit()
    else:
        #If the cardnumber is valid a try is registered in the database
        mycursor.execute("SELECT * FROM mydb.users WHERE cardnum = '" + cardnum + "'")
        if(mycursor.rowcount == 1):
            lock = int(mycursor.fetchone()[6])
            if(lock < 3):
                lock += 1
            mycursor.execute("UPDATE mydb.users SET `lock` = '" + str(lock) + "' WHERE cardnum = '" + cardnum + "'")
        package = {
            'status': 'f'
        }

    mydb.commit()
    package = encrpytPackage(secure_token, package)
    return jsonify(package)

@app.route('/modbal', methods=['GET', 'POST'])
def api_modbal():
    #Decrpyt Package and get Amount and Description
    package = decrpytPackage(request.get_json())
    secure_token = package['secure_token']
    amount = package['amount']
    description = package['description']

    #Authorize the Security Token
    cardnum = authorization(secure_token)
    if(cardnum != 0):
        #If authorization is successful get Account Balance and modify
        mycursor.execute("SELECT account_balance FROM mydb.users WHERE cardnum = '" + cardnum + "'")
        current_balance = str(float(mycursor.fetchone()[0]) + float(amount))
        if(float(current_balance) < 0):  
            print("negative")
            package = {
                'status': 'f'
            }
        else:
            mycursor.execute("UPDATE mydb.users SET `account_balance` = '" + current_balance + "' WHERE cardnum = '" + cardnum + "'")
            #Return modified balance and amount
            package = {
                'status': 's',
                'balance': current_balance,
                'amount': amount
            }
            #Record Transaction
            mycursor.execute("INSERT INTO mydb.transactions (users_cardnum, amount, description) VALUES ('" + 
            cardnum + "', '" +
            amount + "', '" +
            description + "')")
    else:
        #If authorization fails return failure
        package = {
            'status': 'f'
        }
    
    mydb.commit()
    package = encrpytPackage(secure_token, package)
    return jsonify(package)

@app.route('/bill', methods=['GET', 'POST'])
def api_bill():
    #Decrpyt Package and get Authority
    package = decrpytPackage(request.get_json())
    secure_token = package['secure_token']
    authority = package['authority']

    #Authorize the Security Token
    cardnum = authorization(secure_token)
    if(cardnum != 0):
        #If authorization is successful return billed amount
        package = {
            'status': 's',
            'amount': str(random.randint(100, 1000)), #Random placeholder value is returned 
            'authority': authority
        }
    else:
        #If authorization fails return failure
        package = {
            'status': 'f'
        }
    package = encrpytPackage(secure_token, package)
    return jsonify(package)

@app.route('/changepin', methods=['GET', 'POST'])
def api_changepin():
    #Decrpyt Package and get old and new pin
    package = decrpytPackage(request.get_json())
    secure_token = package['secure_token']
    new_pin = package['new_pin']
    old_pin = package['old_pin']

    #Get hashes of the old and new pin
    hash_object = SHA256.new(data=new_pin.encode('utf-8'))
    new_pin_hashed = hash_object.hexdigest()
    hash_object = SHA256.new(data=old_pin.encode('utf-8'))
    old_pin_hashed = hash_object.hexdigest()

    #Authorize the security token
    cardnum = authorization(secure_token)
    #Verify Card Number and Old Hashed Pin with table
    mycursor.execute("SELECT * FROM mydb.users WHERE cardnum = '" + cardnum + "' AND account_pin = '" + old_pin_hashed + "'")

    if(cardnum != 0 and mycursor.rowcount == 1):
        #If authorization and verification are sucessful update new hashed password
        mycursor.execute("UPDATE mydb.users SET account_pin = '" + new_pin_hashed + "' WHERE cardnum = '" + cardnum + "'")
        package = {
            'status': 's'
        }
    else:
        #If authorization fails return failure
        package = {
            'status': 'f'
        }
    
    mydb.commit()
    package = encrpytPackage(secure_token, package)
    return jsonify(package)

@app.route('/transactions', methods=['GET', 'POST'])
def api_transactions():
    #Decrpyt Package
    package = decrpytPackage(request.get_json())
    secure_token = package['secure_token']

    #Authorize token to get card number
    cardnum = authorization(secure_token)

    if(cardnum != 0):
        #If authorization is successful get 20 records for cardnumber in desceding order
        mycursor.execute("SELECT description, UNIX_TIMESTAMP(date) AS DATE FROM mydb.transactions WHERE users_cardnum = '" + cardnum + "' ORDER BY DATE DESC LIMIT 20")
        result = mycursor.fetchall()
        package = {
            'status': 's'
        }
        for i in range(0, len(result)):
            package[str(i)] = str(result[i][0])
    else:
        package = {
            'status': 'f'
        }
    
    package = encrpytPackage(secure_token, package)
    return jsonify(package)

@app.route('/twoFA/update', methods=['GET', 'POST'])
def api_twoFA():
    #Decrpyt Package
    package = decrpytPackage(request.get_json())
    secure_token = package['secure_token']
    code = package['2fac_code']

    #Authorize token to get card number
    cardnum = authorization(secure_token)
    if cardnum != '0':
        mycursor.execute("UPDATE mydb.users SET 2fa_code = '" + code + "' WHERE cardnum = '" + cardnum + "'")
        package = {
            'status': 's'
        }
    else:
        #If authorization fails return failure
        package = {
            'status': 'f'
        }

    mydb.commit()
    package = encrpytPackage(secure_token, package)
    return jsonify(package)

@app.route('/deauth', methods=['GET', 'POST'])
def api_deauth():
    #Decrpyt Package
    package = decrpytPackage(request.get_json())
    secure_token = package['secure_token']

    #Authorize token to get card number
    cardnum = authorization(secure_token)
    if cardnum != '0':
        mycursor.execute("DELETE FROM mydb.sessions WHERE `securetoken` = '" + secure_token + "'")
        package = {
            'status': 's'
        }
    else:
        #If authorization fails return failure
        package = {
            'status': 'f'
        }

    mydb.commit()
    return jsonify(package)

#Encrypt and Hexilify Text
def encrypt(key, text):
    key_pair = RSA.import_key(binascii.unhexlify(key))
    cipher = PKCS1_OAEP.new(key_pair)
    return getStringFromBytes(str(binascii.hexlify(cipher.encrypt(text.encode('utf-8')))))

#Unhexilify and Decrypt Text
def decrypt(key, text):
    key_pair = RSA.import_key(binascii.unhexlify(key))
    cipher = PKCS1_OAEP.new(key_pair)
    return getStringFromBytes(str(cipher.decrypt(binascii.unhexlify(text))))

#Get String Characters from Hex Bytes
def getStringFromBytes(text):
    return re.search("b'(.*)'", text).group(1)

#Imports Key From String Format
def importKey(text):
    return RSA.import_key(binascii.unhexlify(text))

#Encrypt JSON Package
def encrpytPackage(secure_token, package):
    mycursor.execute("SELECT foreign_key FROM mydb.sessions WHERE secureToken = '" + secure_token + "'")
    key = mycursor.fetchone()[0]
    encrypted_package = {}
    for (k, v) in package.items():
        encrypted_package[k] = encrypt(key, v)
    return encrypted_package

#Decrypt JSON Package
def decrpytPackage(package):
    mycursor.execute("SELECT private_key FROM mydb.sessions WHERE secureToken = '" + package['secure_token'] + "'")
    key = mycursor.fetchone()[0]
    secure_token = package.pop('secure_token')
    decrypted_package = {}
    for (k, v) in package.items():
        decrypted_package[k] = decrypt(key, v)
    decrypted_package['secure_token'] = secure_token
    return decrypted_package

#Check Secure Token Authorization
def authorization(secure_token):
    mycursor.execute("SELECT auth, usercardnum FROM mydb.sessions WHERE secureToken = '" + secure_token + "'")
    result = mycursor.fetchone()
    if result[0] == "1":
        return result[1]
    else:
        return 0

app.run()