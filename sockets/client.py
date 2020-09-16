import socket
from tqdm import tqdm
import os
import glob
SEPARATOR = "<SEPARATOR>"
BUFFER_SIZE = 1024 * 4


def send_file(filename, host, port):
    filesize = os.path.getsize(filename)
    s = socket.socket()
    s.connect((host, port))
    s.send(f"{filename}{SEPARATOR}{filesize}".encode())
    with open(filename, "rb") as f:
        for _ in tqdm(range(100)):
            bytes_read = f.read(BUFFER_SIZE)
            if not bytes_read:
                break
            s.sendall(bytes_read)

    s.close()