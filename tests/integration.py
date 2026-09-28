#!/usr/bin/env python3
"""Exercise real HTTPS + FlatBuffers/WebSocket APIs using a disposable database.
Build first: cargo build --workspace. Requires Python 3 and flatc, no pip packages.
--serve keeps the isolated test server running for browser checks on port 3001.
No test data is written to the working installation.
"""
import argparse, base64, json, os, pathlib, socket, sqlite3, ssl, struct, subprocess, tempfile, time, urllib.request, urllib.error
ROOT = pathlib.Path(__file__).resolve().parents[1]
CTX = ssl._create_unverified_context()  # Only the disposable localhost test server.
BASE = 'https://localhost:3001'

def api(path, body=None, token=None, expected=200, method=None):
    headers = {'Content-Type': 'application/json'}
    if token: headers['Authorization'] = 'Bearer ' + token
    req = urllib.request.Request(BASE+path, None if body is None else json.dumps(body).encode(), headers, method=method)
    try: response = urllib.request.urlopen(req, context=CTX, timeout=5)
    except urllib.error.HTTPError as e: response = e
    data = response.read().decode()
    assert response.status == expected, (path,response.status,data)
    try: return json.loads(data)
    except ValueError: return data

class Sensor:
    def __init__(self, key):
        self.sock = CTX.wrap_socket(socket.create_connection(('localhost',3001)),server_hostname='localhost')
        self.sock.settimeout(5)
        nonce = base64.b64encode(os.urandom(16)).decode()
        self.sock.sendall((f'GET /api/router/ws/NET_123 HTTP/1.1\r\nHost: localhost:3001\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {nonce}\r\nSec-WebSocket-Version: 13\r\nAuthorization: ApiKey {key}\r\n\r\n').encode())
        head=b''
        while not head.endswith(b'\r\n\r\n'): head+=self.sock.recv(1)
        assert b'101 Switching Protocols' in head, head
        self.receive() # initial configured threat intelligence, binary
        self.send({'type':'heartbeat','interface':'integration-test','xdp_attached':True})
    def send(self,data):
        opcode=2 if isinstance(data,bytes) else 1
        payload=data if opcode==2 else json.dumps(data).encode()
        mask=os.urandom(4); size=len(payload)
        header=bytes([0x80|opcode,0x80|min(size,126)])+(struct.pack('!H',size) if size>=126 else b'')
        self.sock.sendall(header+mask+bytes(b^mask[i%4] for i,b in enumerate(payload)))
    def read(self,n):
        result=b''
        while len(result)<n:
            chunk=self.sock.recv(n-len(result))
            if not chunk: raise EOFError('WebSocket closed')
            result+=chunk
        return result
    def receive(self):
        opcode,size=self.read(2); size &= 127
        if size==126: size=struct.unpack('!H',self.read(2))[0]
        if size==127: size=struct.unpack('!Q',self.read(8))[0]
        data=self.read(size)
        return json.loads(data) if opcode&15==1 else data
    def close(self): self.sock.close()

def eventually(check):
    for _ in range(40):
        result=check()
        if result:return result
        time.sleep(.1)
    raise AssertionError('Timed out waiting for state')

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--serve',action='store_true');args=parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='cipher-integration-') as tmp:
        tmp=pathlib.Path(tmp)
        env=dict(os.environ,CIPHER_DB=str(tmp/'test.db'),CIPHER_BIND='127.0.0.1:3001',JWT_SECRET='isolated-test-jwt-secret-32-bytes-long',ROUTER_SECRET='isolated-test-router-key',CIPHER_NETWORK_ID='NET_123')
        env.pop('LLM_API_KEY',None);env.pop('CIPHER_THREAT_INTEL_FILE',None)
        with (tmp/'server.log').open('w') as log:
            process=subprocess.Popen([str(ROOT/'target/debug/cipher_backend')],cwd=ROOT/'Server',env=env,stdout=log,stderr=log)
            try:
                for _ in range(100):
                    try:api('/api/health');break
                    except (OSError,urllib.error.URLError):
                        if process.poll() is not None:raise RuntimeError((tmp/'server.log').read_text())
                        time.sleep(.1)
                api('/api/networks',expected=401)
                account={'username':'test-operator','email':'test@example.invalid','password':'test-password-123'}
                token=api('/api/Main/signup',account)
                assert api('/api/networks',token=token)['networks']==[{'network_id':'NET_123','username':'test-operator','is_admin':True}]
                api('/api/owner/set_admin',{'network_id':'OTHER','username':'test-operator','is_admin':True},expected=401)
                other=api('/api/Main/signup',dict(account,username='outsider',email='outsider@example.invalid'))
                api('/api/dashboard/NET_123',token=other,expected=401)
                email_token=api('/api/Main/login',dict(account,username=''))
                assert api('/api/networks',token=email_token)['username']=='test-operator'
                snap=lambda:api('/api/dashboard/NET_123',token=token)
                assert snap()['devices']==[] and snap()['telemetry']==[] and not snap()['sensor_online']
                sensor=Sensor(env['ROUTER_SECRET'])
                payload={'payload_type':'TelemetryReport','payload':{'network_id':'NET_123','mac':'02:00:00:00:00:01','bytes_in':65536,'bytes_out':2048,'total_connections':12,'passed_connections':10,'dropped_connections':2,'port_entropy_score':1.5}}
                def report(network='NET_123'):
                    payload['payload']['network_id']=network
                    (tmp/'report.json').write_text(json.dumps(payload))
                    subprocess.run(['flatc','--binary','-o',str(tmp),str(ROOT/'router.fbs'),str(tmp/'report.json')],check=True)
                    return (tmp/'report.bin').read_bytes()
                sensor.send(b'not-a-flatbuffer')
                sensor.send(report('UNAUTHORIZED_NETWORK'));time.sleep(.2)
                assert snap()['telemetry']==[]
                sensor.send(report());eventually(lambda:len(snap()['telemetry'])==1)
                initial=snap();assert initial['sensor_online'] and initial['devices'][0]['state']=='allowed'
                command={'network_id':'NET_123','mac':'02:00:00:00:00:01','state':'blocked'}
                api('/api/change_state',command,token=other,expected=401)
                request=api('/api/change_state',command,token=token);wire=sensor.receive()
                assert wire['id']==request['id'] and wire['state']=='blocked'
                assert snap()['devices'][0]['state']=='allowed', 'Must not claim applied before ack'
                sensor.send({'type':'command_ack','id':wire['id'],'applied':True,'detail':''})
                eventually(lambda:snap()['devices'][0]['state']=='blocked')
                restore=api('/api/change_state',dict(command,state='allowed'),token=token);wire=sensor.receive()
                sensor.send({'type':'command_ack','id':wire['id'],'applied':False,'detail':'test map update failure'})
                eventually(lambda:snap()['commands'][0]['status']=='failed')
                assert snap()['devices'][0]['state']=='blocked'
                sensor.close();eventually(lambda:not snap()['sensor_online'])
                queued=api('/api/change_state',dict(command,state='allowed'),token=token)
                assert snap()['commands'][0]['status']=='pending'
                sensor=Sensor(env['ROUTER_SECRET']);wire=sensor.receive();assert wire['id']==queued['id']
                sensor.send({'type':'command_ack','id':wire['id'],'applied':True,'detail':''})
                eventually(lambda:snap()['devices'][0]['state']=='allowed')
                # Exercise real statistical screening and persisted review failure.
                stable=report()
                for _ in range(50): sensor.send(stable)
                payload['payload']['bytes_in']=99999999
                sensor.send(report())
                eventually(lambda:len(snap()['incidents'])==1)
                assert snap()['incidents'][0]['threat_name']=='Statistical anomaly'
                assert snap()['devices'][0]['state']=='allowed'
                # A same-network viewer can inspect data but cannot enforce policy.
                with sqlite3.connect(tmp/'test.db') as db:
                    db.execute("INSERT INTO networks VALUES ('NET_123','outsider',0)")
                assert api('/api/dashboard/NET_123',token=other)['devices']
                api('/api/change_state',command,token=other,expected=401)
                sensor.close();eventually(lambda:not snap()['sensor_online'])
                print('PASS: authentication, bootstrap, membership, canonical email login, network-scoped FlatBuffers telemetry, device discovery, pending/applied/failed commands, disconnect, replay, baseline alert persistence and viewer permissions.',flush=True)
                if args.serve:
                    print('Isolated browser fixture ready at https://localhost:3001 (test-operator / test-password-123). Ctrl-C removes the entire fixture.',flush=True)
                    while True:time.sleep(1)
            except Exception:
                print((tmp/"server.log").read_text())
                raise
            finally:
                process.terminate()
                try:process.wait(timeout=5)
                except subprocess.TimeoutExpired:process.kill();process.wait()
if __name__=='__main__':main()
