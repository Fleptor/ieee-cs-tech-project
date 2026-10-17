#!/usr/bin/env python3
"""Exercise both provider adapters and response policy against local HTTP fixtures."""
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import threading
import time
from http.server import ThreadingHTTPServer
ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from cipher_client import Client
from booth import Booth, NETWORK, MAC
from demo_supervisor import Handler

def wait(check,timeout=10):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        result=check()
        if result:return result
        time.sleep(.1)
    raise AssertionError('Timed out')

def exercise(provider):
    with tempfile.TemporaryDirectory(prefix='cipher-supervisor-') as tmp:
        home=pathlib.Path(tmp);cert=home/'cert.pem';key=home/'key.pem'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-keyout',str(key),'-out',str(cert),'-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1','-addext','basicConstraints=critical,CA:TRUE'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        Handler.mode='normal';Handler.calls=0;Handler.delay_seconds=0
        fixture=ThreadingHTTPServer(('127.0.0.1',0),Handler);threading.Thread(target=fixture.serve_forever,daemon=True).start()
        env=dict(os.environ,CIPHER_ENV_FILE=str(home/'no-env'),CIPHER_DB=str(home/'test.db'),CIPHER_BIND='127.0.0.1:3101',CIPHER_TLS_CERT=str(cert),CIPHER_TLS_KEY=str(key),CIPHER_NETWORK_ID=NETWORK,JWT_SECRET='test-secret-at-least-32-bytes-long',ROUTER_SECRET='test-router-key',LLM_PROVIDER=provider,LLM_MODEL='test-fixture',LLM_API_KEY='fixture-key',LLM_BASE_URL=f'http://127.0.0.1:{fixture.server_port}/v1',CIPHER_ALERT_COOLDOWN_SECONDS='120',LLM_TIMEOUT_SECONDS='2')
        env.pop('CIPHER_THREAT_INTEL_FILE',None)
        process=None;booth=None
        with (home/'server.log').open('w') as log:
            try:
                process=subprocess.Popen([str(ROOT/'target/debug/cipher_backend')],cwd=ROOT,env=env,stdout=log,stderr=log)
                client=Client('https://localhost:3101',cert)
                for _ in range(100):
                    try:client.api('/api/health');break
                    except Exception:time.sleep(.1)
                client.token=client.api('/api/Main/signup',{'username':'operator','email':'test@example.invalid','password':'test-password-123'})
                booth=Booth(client,'test-router-key',home);booth.warmup()
                count=len(booth.snapshot()['telemetry'])
                booth.report(report_id='delivery-retry-test');booth.report(report_id='delivery-retry-test')
                wait(lambda:len(booth.snapshot()['telemetry'])==count+1)
                time.sleep(.2);assert len(booth.snapshot()['telemetry'])==count+1
                booth.report(captured_at=int(time.time())-3600,bytes_out=30_000_000,dropped_connections=1000,port_entropy_score=7)
                wait(lambda:len(booth.snapshot()['telemetry'])==count+2)
                assert booth.snapshot()['incidents']==[], 'Historical backlog must not trigger isolation'
                if provider=='openai':
                    # Long gaps between visitors must not stop the command reader.
                    time.sleep(21)
                    booth.api('/api/change_state',mac=MAC,state='blocked')
                    wait(lambda:booth.snapshot()['devices'][0]['state']=='blocked')
                    booth.api('/api/change_state',mac=MAC,state='allowed')
                    wait(lambda:booth.snapshot()['devices'][0]['state']=='allowed')
                def latest():return booth.snapshot()['incidents'][0]
                def attack():
                    before=len(booth.snapshot()['incidents']);booth.report(bytes_out=30_000_000,dropped_connections=1000,port_entropy_score=7)
                    wait(lambda:len(booth.snapshot()['incidents'])>before)
                    wait(lambda:latest()['review_status']!='pending')
                    return latest()
                assert attack()['action']=='observe_only'
                calls=Handler.calls
                for _ in range(5):booth.report(bytes_out=30_000_000,dropped_connections=1000,port_entropy_score=7)
                time.sleep(.4);assert Handler.calls==calls,'Repeated alerts must respect cooldown'
                booth.api('/api/policy',mode='enforce');booth.warmup()
                assert attack()['action']=='isolation_requested'
                wait(lambda:booth.snapshot()['devices'][0]['state']=='blocked')
                booth.api('/api/device/trust',mac=MAC.lower(),trusted=True)
                wait(lambda:booth.snapshot()['devices'][0]['state']=='allowed')
                booth.warmup();assert attack()['action']=='trusted_device'
                assert booth.snapshot()['devices'][0]['trusted']
                assert booth.snapshot()['devices'][0]['state']=='allowed'
                # Manual isolation remains possible for a trusted device.
                booth.api('/api/change_state',mac=MAC,state='blocked');wait(lambda:booth.snapshot()['devices'][0]['state']=='blocked')
                booth.api('/api/change_state',mac=MAC,state='allowed');wait(lambda:booth.snapshot()['devices'][0]['state']=='allowed')
                booth.api('/api/device/trust',mac=MAC,trusted=False)
                for mode in ['unavailable','malformed']:
                    Handler.mode=mode;booth.warmup()
                    assert attack()['review_status']=='failed'
                    assert booth.snapshot()['devices'][0]['state']=='allowed'
                    assert booth.snapshot()['supervisor']['health']['last_error']
                Handler.mode='normal';Handler.delay_seconds=3;booth.warmup()
                assert attack()['review_status']=='failed'
                assert 'timed out' in booth.snapshot()['supervisor']['health']['last_error']
                time.sleep(1.2);Handler.delay_seconds=0
                # Trust granted while a provider is thinking must win over its later verdict.
                Handler.delay_seconds=0.7;booth.warmup()
                before=len(booth.snapshot()['incidents'])
                booth.report(bytes_out=30_000_000,dropped_connections=1000,port_entropy_score=7)
                wait(lambda:len(booth.snapshot()['incidents'])>before)
                booth.api('/api/device/trust',mac=MAC,trusted=True)
                wait(lambda:latest()['review_status']=='complete')
                assert latest()['action']=='trusted_device'
                Handler.delay_seconds=0
                booth.api('/api/device/trust',mac=MAC,trusted=False)
                Handler.mode='normal';booth.warmup()
                # One anomalous feature is insufficient for auto-isolation even with a valid LLM answer.
                count=len(booth.snapshot()['incidents']);booth.report(bytes_in=25_000_000)
                wait(lambda:len(booth.snapshot()['incidents'])>count and latest()['review_status']=='complete')
                assert latest()['action']=='review_only'
                # Persistent baseline/trust/policy survive process replacement.
                booth.api('/api/device/trust',mac=MAC,trusted=True);wait(lambda:booth.snapshot()['devices'][0]['trusted'])
                booth.close();booth=None;process.terminate();process.wait(timeout=5)
                process=subprocess.Popen([str(ROOT/'target/debug/cipher_backend')],cwd=ROOT,env=env,stdout=log,stderr=log)
                for _ in range(100):
                    try:client.api('/api/health');break
                    except Exception:time.sleep(.1)
                snapshot=client.api('/api/dashboard/'+NETWORK)
                assert snapshot['devices'][0]['trusted'] and snapshot['policy']['mode']=='enforce'
                assert snapshot['baselines'][0]['samples']==50
                print(f'PASS: {provider} API, cooldown, observe/enforce/trust/manual response, malformed/503 fallback and restart persistence',flush=True)
            except Exception:
                print((home/'server.log').read_text());raise
            finally:
                if booth:booth.close()
                if process:
                    process.terminate()
                    try:process.wait(timeout=5)
                    except subprocess.TimeoutExpired:process.kill();process.wait()
                fixture.shutdown();fixture.server_close()

if __name__=='__main__':
    for provider in ['anthropic','openai']:exercise(provider)
