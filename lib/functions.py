from werkzeug.security import generate_password_hash, check_password_hash
from lib import mySQLCon as mc
from lib import keyGen as kg
from lib.config import *
from random import randint
import os

def connect_to_DB():
    if os.getenv('SERVER_SOFTWARE', '').startswith('Google App Engine/'):
        db = mc.DataBase(CLOUDSQL_CONNECTION_NAME,CLOUDSQL_USER,CLOUDSQL_PASSWORD,CLOUDSQL_DATABASE,'GCSQL')
    else:
        db = mc.DataBase(SERVER,USERNAME,PASSWORD,DATABASE,'LOCAL')
    return db

def save_user_pass(userData, db):
    userid = randint(0,100)
    sql = "INSERT INTO users (uid,username,password,isadmin) VALUES (%s,%s,%s,%s)"
    username = userData[0][1]
    password = generate_password_hash(userData[1][1])
    parameters = (userid, username, password, False)
    db.insert(sql, parameters)
    return userid, username

def save_pub_priv(userid, publickey, privatekey,db):
    keyid = randint(0,100)
    sql = "INSERT INTO securekeys (keyid,userid,publickey,privatekey) VALUES (%s,%s,%s,%s)"
    parameters = (keyid, userid, publickey, privatekey)
    db.insert(sql, parameters)

def save_pub_key(userid, username, publickey,db):
    keyid = randint(0,100)
    sql = "INSERT INTO publickeys (keyid,username,publickey,userid) VALUES (%s,%s,%s,%s)"
    parameters = (keyid, username, publickey, userid)
    db.insert (sql, parameters)

def keys_and_save(user_list):
    keyGen = kg.RSAEncryption()
    publickey, privatekey = keyGen.generate_keys()
    db = connect_to_DB()
    userid, username = save_user_pass(user_list,db)
    save_pub_priv(userid,publickey,privatekey,db)
    save_pub_key(userid,username,publickey,db)
    db.commit()

def fetch_username_and_password(username, password):
    db = connect_to_DB()
    sql = "SELECT * FROM users WHERE username = %s"
    arguments = (username,)
    result = db.query(sql,arguments)
    if result:
        authentication = check_password_hash(result[0][2],password)
        if authentication:
            if result[0][3] == 1:
                isadmin = True
            else:
                isadmin = False
            return (True,isadmin)
        else:    
            return (False,False)
    else:
        return (False,False)

def get_privatekey(username):
    userid = fetch_userid(username)
    db = connect_to_DB()
    sql = "SELECT privatekey FROM securekeys WHERE userid = (%s)"
    parameters = (userid,)
    result = db.query(sql,parameters)
    return result[0][0]

def fetch_users_public():
    db = connect_to_DB()
    sql = "SELECT username,publicKey,userid FROM publickeys"
    queryResult = db.query(sql,None)
    username = [x for x,y,z in queryResult]
    publickey = [y for x,y,z in queryResult]
    userid = [z for x,y,z in queryResult]
    publicKeyDict = dict(zip(username,publickey))
    userIdDict = dict(zip(username,userid))
    return publicKeyDict, userIdDict

def fetch_userid(username):
    db = connect_to_DB()
    sql = "SELECT uid from users WHERE username =(%s)"
    parameters = (username,)
    result = db.query(sql, parameters)
    return result[0][0]

def save_secure_message(message,signature,user):
    messageid = randint(0,100)
    db = connect_to_DB()
    sql = "INSERT INTO messages (mid,message,user,signature) VALUES (%s,%s,%s,%s)"
    parameters = (messageid,message,user,signature)
    db.insert(sql,parameters)
    db.commit()

def send_message (message, realUser, claimingUser):
    if claimingUser == None:
        whoPosted = realUser
    else:
        whoPosted = claimingUser
    keyGen = kg.RSAEncryption()
    privatekey = get_privatekey(realUser)
    signature = keyGen.generate_signature(message,privatekey)
    save_secure_message(message,signature,whoPosted)

def check_signature(messageList):
    resultList = []
    keyGen = kg.RSAEncryption()
    publickeyDict = fetch_users_public()[0]
    for elements in messageList:
        sender = elements[1]
        publickey = publickeyDict[sender]
        message = elements [0]
        signature = elements[2]
        authenticity = keyGen.verifying_signature(message,signature,publickey)
        resultList.append((message,sender,authenticity))
    return resultList

def receive_messages():
    messages = []
    db = connect_to_DB()
    sql = "SELECT message, user, signature FROM messages"
    results = db.query(sql,None)
    messageList = check_signature(results)
    return messageList