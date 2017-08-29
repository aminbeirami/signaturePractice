#Written By Amin Beirami
import os
#MySQL configuration

SERVER = '127.0.0.1'
USERNAME = "root"
PASSWORD = "amin123"
DATABASE = "secure_signature"

#SecretKey is used to encrypt the session cookies

SECRET_KEY = os.urandom(24)