"""Small stdlib client for isolated booth scenarios and integration checks."""
import base64
import json
import os
import socket
import ssl
import struct
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

class Client:
    def __init__(self, base, cert):
        self.base=base.rstrip('/')
        self.context=ssl.create_default_context(cafile=str(cert))
        self.token=None
    def refresh_session(self):
        """Keep an unattended booth operator usable across the two-hour JWT lifetime."""
        if not self.token:return
        body=self.token.split('.')[1]
        expires=json.loads(base64.urlsafe_b64decode(body+'='*(-len(body)%4)))['exp']
        if expires-time.time()<900:
            self.token=self.api('/api/session/refresh',{})
    def api(self,path,body=None,method=None):
        headers={'Content-Type':'application/json'}
        if self.token: headers['Authorization']='Bearer '+self.token
        request=urllib.request.Request(self.base+path,None if body is None else json.dumps(body).encode(),headers,method=method)
        try:
            with urllib.request.urlopen(request,context=self.context,timeout=65) as response:
                text=response.read().decode()
        except urllib.error.HTTPError as error:
            raise RuntimeError(f'{path}: HTTP {error.code}: {error.read().decode()}') from error
        try: return json.loads(text)
        except ValueError: return text

class WireSensor:
    def __init__(self,client,network,key):
        url=urllib.parse.urlparse(client.base)
        self.sock=client.context.wrap_socket(socket.create_connection((url.hostname,url.port or 443),timeout=5),server_hostname=url.hostname)
        # A dedicated reader must survive an idle booth; close() interrupts this read.
        self.sock.settimeout(None)
        self.lock=threading.Lock()
        nonce=base64.b64encode(os.urandom(16)).decode()
        path='/api/router/ws/'+urllib.parse.quote(network,safe='')
        self.sock.sendall((f'GET {path} HTTP/1.1\r\nHost: {url.netloc}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {nonce}\r\nSec-WebSocket-Version: 13\r\nAuthorization: ApiKey {key}\r\n\r\n').encode())
        head=b''
        while not head.endswith(b'\r\n\r\n'):
            chunk=self.sock.recv(1)
            if not chunk: raise EOFError('Handshake closed')
            head+=chunk
        if b'101 Switching Protocols' not in head: raise RuntimeError('Sensor handshake rejected')
    def frame(self,opcode,payload):
        mask=os.urandom(4);size=len(payload)
        header=bytes([0x80|opcode,0x80|(size if size<126 else 126 if size<65536 else 127)])
        if size>=65536:header+=struct.pack('!Q',size)
        elif size>=126:header+=struct.pack('!H',size)
        with self.lock:self.sock.sendall(header+mask+bytes(b^mask[i%4] for i,b in enumerate(payload)))
    def send(self,data):
        self.frame(2 if isinstance(data,bytes) else 1,data if isinstance(data,bytes) else json.dumps(data).encode())
    def read(self,n):
        data=b''
        while len(data)<n:
            chunk=self.sock.recv(n-len(data))
            if not chunk: raise EOFError('Sensor disconnected')
            data+=chunk
        return data
    def receive(self):
        while True:
            first,second=self.read(2);opcode=first&15;size=second&127
            if size==126:size=struct.unpack('!H',self.read(2))[0]
            elif size==127:size=struct.unpack('!Q',self.read(8))[0]
            payload=self.read(size)
            if opcode==8:raise EOFError('Server closed sensor')
            if opcode==9:self.frame(10,payload);continue
            if opcode==10:continue
            return json.loads(payload) if opcode==1 else payload
    def close(self):
        try:self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:pass
        self.sock.close()
