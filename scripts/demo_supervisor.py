#!/usr/bin/env python3
"""Deterministic booth fixture. Does NOT run an AI model. Binds only to loopback."""
import argparse
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class Handler(BaseHTTPRequestHandler):
    mode='normal'
    calls=0
    delay_seconds=0
    def log_message(self,*args):pass
    def do_POST(self):
        type(self).calls+=1
        body=json.loads(self.rfile.read(int(self.headers.get('Content-Length','0'))))
        time.sleep(self.delay_seconds)
        if self.mode=='unavailable':self.send_error(503,'Booth fixture outage');return
        evidence=json.loads(body['messages'][-1]['content'])
        reasons=evidence.get('measurements',{}).get('reasons',[])
        values=evidence.get('measurements',{}).get('values',[0,0,0,0])
        suspicious=len(reasons)>=2
        name='Unusual outbound activity' if values[1]>1_000_000 else 'Possible scan activity' if values[3]>4 else 'Unusual traffic volume'
        verdict={'threat_name':'[DEMO] '+name,'confidence':95 if suspicious else 40,'human_explanation':'DEMO FIXTURE — deterministic response, not model reasoning. '+('Multiple measurements changed. Investigate the device and destinations.' if suspicious else 'A volume spike alone can be a legitimate download; investigate before isolating.'),'should_block':suspicious}
        content='invalid verdict' if self.mode=='malformed' else json.dumps(verdict)
        result={'content':[{'type':'text','text':content}],'stop_reason':'end_turn'} if self.path.endswith('/messages') else {'choices':[{'message':{'content':content},'finish_reason':'stop'}]}
        data=json.dumps(result).encode();self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)));self.end_headers()
        try:self.wfile.write(data)
        except (BrokenPipeError,ConnectionResetError):pass

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--port',type=int,default=3102);p.add_argument('--mode',choices=['normal','unavailable','malformed'],default='normal');args=p.parse_args()
    Handler.mode=args.mode
    print(f'DEMO supervisor fixture on 127.0.0.1:{args.port}; no AI model is running.',flush=True)
    ThreadingHTTPServer(('127.0.0.1',args.port),Handler).serve_forever()
