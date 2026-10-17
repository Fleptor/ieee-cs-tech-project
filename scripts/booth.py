#!/usr/bin/env python3
"""Isolated, repeatable CIPHER booth rehearsal. Run `start`, then `hook NAME`."""
import argparse
import json
import os
import pathlib
import secrets
import signal
import socket
import subprocess
import sys
import threading
import tempfile
import time
import uuid
from http.server import ThreadingHTTPServer
from cipher_client import Client, WireSensor
from demo_supervisor import Handler

ROOT=pathlib.Path(__file__).resolve().parents[1]
HOME=ROOT/'.local/booth'
NETWORK='BOOTH_DEMO'
MAC='02:00:00:00:00:0A'
SCENARIOS=['normal','download','scan','exfil','trust','revoke','isolate','restore','enforce','observe','disconnect','command-failure','llm-outage','llm-recover','malformed-llm','reset','export','status']

class Booth:
    def __init__(self,client,key,home):
        self.client=client;self.key=key;self.home=home;self.sensor=None;self.policy={};self.blocked=False;self.fail_next=False;self.closed=False;self.error=None
        self.connect()
        threading.Thread(target=self.heartbeat,daemon=True).start()
    def connect(self):
        sensor=WireSensor(self.client,NETWORK,self.key);self.sensor=sensor
        threading.Thread(target=self.reader,args=(sensor,),daemon=True).start()
        sensor.send({'type':'heartbeat','interface':'booth-simulator','xdp_attached':False,'simulated':True})
    def reader(self,sensor):
        try:
            while not self.closed:
                message=sensor.receive()
                if not isinstance(message,dict):continue
                if message.get('type')=='policy':
                    self.policy=message
                    sensor.send({'type':'policy_ack','revision':message['revision'],'applied':True})
                elif message.get('type')=='device_command':
                    applied=not self.fail_next;self.fail_next=False
                    if message.get('automatic') and (self.policy.get('mode')!='enforce' or message['mac'] in self.policy.get('trusted_macs',[]) or self.policy.get('revision')!=message.get('policy_revision')):applied=False
                    if applied:self.blocked=message['state']=='blocked'
                    sensor.send({'type':'command_ack','id':message['id'],'applied':applied,'detail':'Simulated sensor acknowledgment; no packets were blocked' if applied else 'Simulated map operation failure'})
        except (OSError,EOFError) as error:
            if not self.closed and self.sensor is sensor:self.error=str(error)
    def heartbeat(self):
        while not self.closed:
            time.sleep(5)
            try:
                if self.sensor:self.sensor.send({'type':'heartbeat','interface':'booth-simulator','xdp_attached':False,'simulated':True})
            except OSError:pass
    def api(self,path,**payload):return self.client.api(path,dict(network_id=NETWORK,**payload))
    def report(self,**changes):
        value=dict(network_id=NETWORK,mac=MAC,bytes_in=65536,bytes_out=2048,total_connections=100,passed_connections=100,dropped_connections=0,unique_external_ips=4,port_entropy_score=1.0,captured_at=int(time.time()),report_id=uuid.uuid4().hex)
        value.update(changes)
        source=self.home/'report.json';source.write_text(json.dumps({'payload_type':'TelemetryReport','payload':value}))
        subprocess.run(['flatc','--binary','-o',str(self.home),str(ROOT/'router.fbs'),str(source)],check=True,stdout=subprocess.DEVNULL)
        if not self.sensor:raise RuntimeError('Sensor is disconnected')
        self.sensor.send((self.home/'report.bin').read_bytes())
    def wait(self,check,timeout=8):
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            value=check()
            if value:return value
            time.sleep(.1)
        raise RuntimeError('Timed out waiting for server state')
    def snapshot(self):return self.client.api('/api/dashboard/'+NETWORK)
    def warmup(self):
        self.report()
        source=self.home/'register.json'
        source.write_text(json.dumps({'payload_type':'RegisterRequest','payload':{'network_id':NETWORK,'mac':MAC,'hostname':'Booth demo device','ip':'192.0.2.10','manufacturer':'Simulated sensor'}}))
        subprocess.run(['flatc','--binary','-o',str(self.home),str(ROOT/'router.fbs'),str(source)],check=True,stdout=subprocess.DEVNULL)
        self.sensor.send((self.home/'register.bin').read_bytes())
        self.wait(lambda:len(self.snapshot()['devices'])==1)
        self.api('/api/device/baseline/reset',mac=MAC)
        for i in range(50):self.report(bytes_in=65000+(i%5)*500,bytes_out=2000+(i%4)*100)
        self.wait(lambda:any(b['samples']==50 for b in self.snapshot()['baselines']))
    def hook(self,name):
        if name=='normal':self.report()
        elif name in ('download','scan','exfil'):
            self.warmup()
            if name=='download':self.report(bytes_in=25_000_000)
            elif name=='scan':self.report(total_connections=1500,passed_connections=300,dropped_connections=1200,unique_external_ips=80,port_entropy_score=7.5,anomaly_flags_count=80)
            else:self.report(bytes_out=30_000_000,dropped_connections=100,unique_external_ips=70,port_entropy_score=6.0)
        elif name=='trust':self.api('/api/device/trust',mac=MAC,trusted=True)
        elif name=='revoke':self.api('/api/device/trust',mac=MAC,trusted=False)
        elif name in ('isolate','restore'):self.api('/api/change_state',mac=MAC,state='blocked' if name=='isolate' else 'allowed')
        elif name in ('enforce','observe'):self.api('/api/policy',mode=name)
        elif name=='disconnect':
            old=self.sensor;self.sensor=None;old.close()
            self.wait(lambda:not self.snapshot()['sensor_online'])
            print('Sensor offline for 10 seconds. Queue a response in the dashboard to demonstrate replay.',flush=True)
            time.sleep(10);self.connect()
        elif name=='command-failure':
            self.fail_next=True;self.api('/api/change_state',mac=MAC,state='blocked')
        elif name in ('llm-outage','llm-recover','malformed-llm'):
            Handler.mode={'llm-outage':'unavailable','llm-recover':'normal','malformed-llm':'malformed'}[name]
        elif name=='reset':
            Handler.mode='normal';self.fail_next=False
            self.api('/api/policy',mode='observe');self.api('/api/device/trust',mac=MAC,trusted=False)
            self.api('/api/change_state',mac=MAC,state='allowed')
            for incident in self.snapshot()['incidents']:
                if incident['disposition']=='open':self.api('/api/incidents/review',id=incident['id'],disposition='resolved',note='Booth reset; history retained')
            self.warmup()
        elif name=='export':
            target=self.home/'telemetry-export.json';target.write_text(json.dumps(self.client.api('/api/telemetry/'+NETWORK),indent=2));return {'saved':str(target)}
        elif name!='status':raise ValueError('Unknown scenario')
        time.sleep(.3)
        snap=self.snapshot()
        return {'scenario':name,'sensor_error':self.error,'mode':snap['policy']['mode'],'sensor_online':snap['sensor_online'],'devices':[{k:d[k] for k in ['mac','trusted','state']} for d in snap['devices']],'latest_incident':snap['incidents'][0] if snap['incidents'] else None}
    def close(self):
        self.closed=True
        if self.sensor:self.sensor.close()

def main():
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='command',required=True)
    start=sub.add_parser('start');start.add_argument('--llm',choices=['fixture','configured','off'],default='fixture');start.add_argument('--port',type=int,default=3100);start.add_argument('--fixture-port',type=int,default=3102)
    hook=sub.add_parser('hook');hook.add_argument('scenario',choices=SCENARIOS)
    args=parser.parse_args();HOME.mkdir(parents=True,exist_ok=True);HOME.chmod(0o700)
    if args.command=='hook':
        inbox=HOME/'inbox'
        if not (HOME/'running.json').exists():raise SystemExit('Start the booth runner first.')
        name=uuid.uuid4().hex;target=inbox/(name+'.json');pending=inbox/(name+'.tmp');pending.write_text(json.dumps({'scenario':args.scenario}));pending.rename(target)
        result=HOME/(name+'.result')
        for _ in range(900):
            if result.exists():
                data=json.loads(result.read_text());result.unlink();print(json.dumps(data,indent=2));return 1 if 'error' in data else 0
            time.sleep(.1)
        raise SystemExit('Booth hook timed out; check the runner terminal.')
    if (HOME/'running.json').exists():
        running=json.loads((HOME/'running.json').read_text())
        try:os.kill(running['pid'],0)
        except ProcessLookupError:pass
        else:raise SystemExit('A booth runner is already active. Stop it with Ctrl-C before starting another.')
    # Bind check prevents accidentally talking to an unrelated existing server.
    with socket.socket() as probe:
        probe.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        probe.bind(('127.0.0.1',args.port))
    data_root=pathlib.Path(os.environ.get('CIPHER_BOOTH_DATA_DIR',tempfile.gettempdir()))
    data_root.mkdir(parents=True,exist_ok=True)
    session=pathlib.Path(tempfile.mkdtemp(prefix='cipher-booth-',dir=data_root))
    (HOME/'inbox').mkdir(exist_ok=True)
    for old in (HOME/'inbox').glob('*.json'):old.unlink()
    cert=session/'localhost.pem';keyfile=session/'localhost-key.pem'
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','2','-keyout',str(keyfile),'-out',str(cert),'-subj','/CN=CIPHER booth','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1','-addext','basicConstraints=critical,CA:TRUE'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    keyfile.chmod(0o600)
    router_key=secrets.token_hex(32);password=secrets.token_urlsafe(16)
    env=dict(os.environ,CIPHER_ENV_FILE=str(ROOT/'.local/cipher.env'),CIPHER_DB=str(session/'booth.db'),CIPHER_BIND=f'127.0.0.1:{args.port}',CIPHER_NETWORK_ID=NETWORK,CIPHER_TLS_CERT=str(cert),CIPHER_TLS_KEY=str(keyfile),JWT_SECRET=secrets.token_hex(32),ROUTER_SECRET=router_key,CIPHER_DEMO_MODE='1',CIPHER_ALERT_COOLDOWN_SECONDS='2')
    fixture=None;process=None;booth=None
    try:
        if args.llm=='fixture':
            fixture=ThreadingHTTPServer(('127.0.0.1',args.fixture_port),Handler);threading.Thread(target=fixture.serve_forever,daemon=True).start()
            env.update(LLM_PROVIDER='openai',LLM_MODEL='booth-fixture',LLM_API_KEY='local-fixture',LLM_BASE_URL=f'http://127.0.0.1:{args.fixture_port}/v1',LLM_TOKEN_PARAMETER='max_completion_tokens')
        elif args.llm=='off':env.update(LLM_MODEL='',LLM_API_KEY='')
        with (session/'server.log').open('w') as log:
            process=subprocess.Popen([str(ROOT/'target/debug/cipher_backend')],cwd=ROOT,env=env,stdout=log,stderr=log)
            client=Client(f'https://localhost:{args.port}',cert)
            for _ in range(600):
                try:client.api('/api/health');break
                except Exception:
                    if process.poll() is not None:raise RuntimeError((session/'server.log').read_text())
                    time.sleep(.1)
            else:raise RuntimeError('Server did not become ready; inspect '+str(session/'server.log'))
            client.token=client.api('/api/Main/signup',{'username':'booth-operator','email':'booth@example.invalid','password':password})
            booth=Booth(client,router_key,session);booth.warmup()
            (HOME/'running.json').write_text(json.dumps({'pid':os.getpid(),'session':str(session),'url':client.base}))
            credentials=session/'operator.txt';credentials.write_text(f'URL: {client.base}\nUsername: booth-operator\nPassword: {password}\n');credentials.chmod(0o600)
            print(f'BOOTH SIMULATION: {client.base}\nOperator login: {credentials}\nSupervisor: {args.llm}'+(' (deterministic fixture; no AI model)' if fixture else '')+'\nRun: python3 scripts/booth.py hook scan\nCtrl-C stops the isolated server. Sessions are retained for review.',flush=True)
            while True:
                if process.poll() is not None:raise RuntimeError('Booth server stopped; inspect '+str(session/'server.log'))
                for path in sorted((HOME/'inbox').glob('*.json')):
                    try:
                        name=json.loads(path.read_text())['scenario']
                        if name in ('llm-outage','llm-recover','malformed-llm') and not fixture:raise ValueError('This hook requires --llm fixture')
                        result=booth.hook(name)
                    except Exception as error:result={'error':str(error)}
                    (HOME/(path.stem+'.result')).write_text(json.dumps(result));path.unlink()
                    print('Hook completed:',name,flush=True)
                time.sleep(.2)
    except KeyboardInterrupt:pass
    finally:
        (HOME/'running.json').unlink(missing_ok=True)
        if booth:booth.close()
        if process:
            process.terminate()
            try:process.wait(timeout=5)
            except subprocess.TimeoutExpired:process.kill();process.wait()
        if fixture:fixture.shutdown();fixture.server_close()
    return 0
if __name__=='__main__':sys.exit(main() or 0)
