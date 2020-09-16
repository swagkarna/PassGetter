import configparser
import ctypes as ct
import json
import logging
import os
import select
import sqlite3
import sys
from base64 import b64decode
from getpass import getpass
from subprocess import PIPE, Popen, DEVNULL

SYS64 = sys.maxsize > 2**32

SYS_ENCODING , LIB_ENCODING = "utf8", "utf8"

USR_ENCODING = sys.stdin.encoding or sys.stdout.encoding or "utf8"

CONFIG = {}

def _decode(_bytes, encoding=USR_ENCODING):
    return _bytes

def _encode(_unicode, encoding=USR_ENCODING):
    return _unicode

class Credentials(object):
    """Base credentials backend manager
    """
    def __init__(self, db):
        self.db = db

    def __iter__(self):
        pass

    def done(self):
        """Override this method if the credentials subclass needs to do any
        action after interaction
        """
        pass

class JsonCredentials(Credentials):
    def __init__(self, profile):
        db = os.path.join(profile, "logins.json")

        super(JsonCredentials, self).__init__(db)

    def __iter__(self):
        with open(self.db) as fh:
            data = json.load(fh)

            try:
                logins = data["logins"]
            except Exception:
                sys.exit()

            for i in logins:
                yield (i["hostname"], i["encryptedUsername"],
                       i["encryptedPassword"], i["encType"])

class NSSDecoder(object):
    class SECItem(ct.Structure):
        
        _fields_ = [
            ('type', ct.c_uint),
            ('data', ct.c_char_p),  # actually: unsigned char *
            ('len', ct.c_uint),
        ]

    class PK11SlotInfo(ct.Structure):
        ""

    def __init__(self):
        self.NSS = None
        self.load_libnss()

        SlotInfoPtr = ct.POINTER(self.PK11SlotInfo)
        SECItemPtr = ct.POINTER(self.SECItem)

        self._set_ctypes(ct.c_int, "NSS_Init", ct.c_char_p)
        self._set_ctypes(ct.c_int, "NSS_Shutdown")
        self._set_ctypes(SlotInfoPtr, "PK11_GetInternalKeySlot")
        self._set_ctypes(None, "PK11_FreeSlot", SlotInfoPtr)
        self._set_ctypes(ct.c_int, "PK11_CheckUserPassword", SlotInfoPtr, ct.c_char_p)
        self._set_ctypes(ct.c_int, "PK11SDR_Decrypt", SECItemPtr, SECItemPtr, ct.c_void_p)
        self._set_ctypes(None, "SECITEM_ZfreeItem", SECItemPtr, ct.c_int)

        # for error handling
        self._set_ctypes(ct.c_int, "PORT_GetError")
        self._set_ctypes(ct.c_char_p, "PR_ErrorToName", ct.c_int)
        self._set_ctypes(ct.c_char_p, "PR_ErrorToString", ct.c_int, ct.c_uint32)

    def _set_ctypes(self, restype, name, *argtypes):
        """Set input/output types on libnss C functions for automatic type casting
        """
        res = getattr(self.NSS, name)
        res.restype = restype
        res.argtypes = argtypes
        setattr(self, "_" + name, res)

    @staticmethod
    def find_nss(locations, nssname):
        """Locate nss is one of the many possible locations
        """
        fail_errors = []

        for loc in locations:
            nsslib = os.path.join(loc, nssname)

            try:
                nss = ct.CDLL(nsslib)
            except OSError as e:
                fail_errors.append((nsslib, str(e)))
            else:
                return nss

    def load_libnss(self):
        nssname = "libnss3.so"
        if SYS64:
            locations = (
                    "",  # Current directory or system lib finder
                    "/usr/lib64",
                    "/usr/lib64/nss",
                    "/usr/lib",
                    "/usr/lib/nss",
                    "/usr/local/lib",
                    "/usr/local/lib/nss",
                    "/opt/local/lib",
                    "/opt/local/lib/nss",
                    os.path.expanduser("~/.nix-profile/lib"),
                )
        else:
            locations = (
                    "",  # Current directory or system lib finder
                    "/usr/lib",
                    "/usr/lib/nss",
                    "/usr/lib32",
                    "/usr/lib32/nss",
                    "/usr/lib64",
                    "/usr/lib64/nss",
                    "/usr/local/lib",
                    "/usr/local/lib/nss",
                    "/opt/local/lib",
                    "/opt/local/lib/nss",
                    os.path.expanduser("~/.nix-profile/lib"),
                )

        # If this succeeds libnss was loaded
        self.NSS = self.find_nss(locations, nssname)

    def handle_error(self):

        code = self._PORT_GetError()
        name = self._PR_ErrorToName(code)
        name = "NULL" if name is None else name.decode(SYS_ENCODING)
        text = self._PR_ErrorToString(code, 0)
        text = text.decode(SYS_ENCODING)

    def decode(self, data64):
        data = b64decode(data64)
        inp = self.SECItem(0, data, len(data))
        out = self.SECItem(0, None, 0)

        e = self._PK11SDR_Decrypt(inp, out, None)
        try:
            if e == -1:
                self.handle_error()

            res = ct.string_at(out.data, out.len).decode(LIB_ENCODING)
        finally:
            self._SECITEM_ZfreeItem(out, 0)

        return res

def decode_entry(user64, passw64):

        user = NSS.decode(user64)

        passw = NSS.decode(passw64)

        return user, passw

def obtain_credentials(profile):
    
    try:
        credentials = JsonCredentials(profile)
    except:
        pass

    return credentials

def read_config(filename):

    if os.path.isfile(filename):
            
        config = configparser.ConfigParser()
        config.read(filename)

        CONFIG["global"] = {
            "profile0": config.get("Profile0", "Path").replace("/", "\\"),
            "profile1": config.get("Profile1", "Path").replace("/", "\\")
        }

        return True

    else:
        print("Configuration file " + filename + " not found!")
        sys.exit("Exiting.")

        return False

def load_profile(profile):

        profile = profile.encode(LIB_ENCODING)

        e = NSS._NSS_Init(b"sql:" + profile)

        if e != 0:
            NSS.handle_error()

def unload_profile():
        """Shutdown NSS and deactivate current profile
        """
        e = NSS._NSS_Shutdown()

        if e != 0:
            NSS.handle_error()

def decrypt_passwords():

    profile = os.getenv("HOME") + "/.mozilla/firefox/" + CONFIG["global"]["profile0"]

    load_profile(profile)

    got_password = False
    header = True

    credentials = obtain_credentials(profile)

    for url, user, passw, enctype in credentials:
        got_password = True

        if enctype:
            user, passw = decode_entry(user, passw)

        conn = sqlite3.connect("firepass.db")
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE passwords(url, username, password)''')
        cursor.execute("INSERT INTO passwords (url, username, password) VALUES (?, ?, ?)", (url, user, passw))
        conn.commit()

        credentials.done()

    unload_profile()


NSS = NSSDecoder()
read_config(os.getenv("HOME") + "/.mozilla/firefox/profiles.ini")