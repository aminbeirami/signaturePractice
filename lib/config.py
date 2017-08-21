#Written By Amin Beirami
import os
#MySQL configuration

SERVER = '127.0.0.1'
USERNAME = "root"
PASSWORD = "db password"
DATABASE = "db name"

#SecretKey is used to encrypt the session cookies

SECRET_KEY = os.urandom(24)