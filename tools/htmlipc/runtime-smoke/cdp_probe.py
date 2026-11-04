"""Read-only loopback CEF event observer for a fresh unauthenticated fixture."""
import json,re,threading,time,urllib.parse,urllib.request
class Observer:
 def __init__(self,port):
  self.port=port;self.stop=threading.Event();self.events=[];self.attached=0;self.requests={};self.sockets={}
  self.thread=threading.Thread(target=self.run,daemon=True);self.thread.start()
 def url(self,value):
  try:
   u=urllib.parse.urlsplit(value)
   if u.username or u.password:return '[private-url]'
   host=(u.hostname or '').lower()
   # Keep only public test/static origins and static-resource paths, never queries.
   if host not in ('steamloopback.host','localhost','127.0.0.1') and not host.endswith(('.steampowered.com','.steamstatic.com','.steamcommunity.com')):return '[external-origin]'
   path=re.sub(r'[A-Za-z0-9_-]{48,}','[opaque]',u.path)[:240]
   return (u.scheme+'://'+host+path)[:320]
  except Exception:return '[url]'
 def message(self,value):
  if not isinstance(value,str):return ''
  value=re.sub(r'(?:https?|wss?)://[^\s\"<>]+',lambda m:self.url(m[0]),value)
  value=re.sub(r'(?i)(authorization|cookie|password|ticket|access_token|refresh_token|sessionid|steamid)\s*[:=]\s*[^\s,;]+',r'\1=[redacted]',value)
  value=re.sub(r'[A-Za-z0-9_+/=-]{48,}','[opaque]',value)
  return ''.join(c for c in value if c=='\n' or ord(c)>=32)[:700]
 def add(self,event):
  if len(self.events)<100:self.events.append(event)
 def receive(self,payload):
  method=payload.get('method','');p=payload.get('params',{})
  if method=='Network.requestWillBeSent':
   if len(self.requests)<2048:self.requests[p.get('requestId','')]={'url':self.url(p.get('request',{}).get('url','')),'type':p.get('type','')}
  elif method=='Network.responseReceived':
   response=p.get('response',{});status=response.get('status',0)
   if status>=400:self.add({'kind':'response','url':self.url(response.get('url','')),'status':status,'type':p.get('type','')})
  elif method=='Network.loadingFailed':
   row=self.requests.get(p.get('requestId',''),{})
   self.add({'kind':'loading-failed',**row,'error':self.message(p.get('errorText','')),'cancelled':p.get('canceled',False)})
  elif method=='Runtime.exceptionThrown':
   d=p.get('exceptionDetails',{});e=d.get('exception',{})
   self.add({'kind':'exception','text':self.message(e.get('description') or d.get('text','')),'url':self.url(d.get('url','')),'line':d.get('lineNumber',0),
    'frames':[{'function':self.message(f.get('functionName','')),'url':self.url(f.get('url','')),'line':f.get('lineNumber',0),'column':f.get('columnNumber',0)} for f in d.get('stackTrace',{}).get('callFrames',[])[:8]]})
  elif method=='Runtime.consoleAPICalled' and p.get('type') in ('error','warning','warn'):
   text=' '.join(a.get('value','') for a in p.get('args',[]) if a.get('type')=='string' and isinstance(a.get('value'),str))
   self.add({'kind':'console','level':p.get('type'),'text':self.message(text)})
  elif method=='Log.entryAdded':
   e=p.get('entry',{})
   if e.get('level') in ('error','warning'):self.add({'kind':'log','source':e.get('source'),'level':e.get('level'),'text':self.message(e.get('text','')),'url':self.url(e.get('url',''))})
 def run(self):
  import websocket
  next_discover=0
  while not self.stop.is_set():
   if time.monotonic()>=next_discover:
    next_discover=time.monotonic()+1
    try:
     with urllib.request.urlopen('http://127.0.0.1:'+str(self.port)+'/json/list',timeout=.5) as r:targets=json.loads(r.read(262144))
     for target in targets:
      if target.get('type')!='page' or len(self.sockets)>=8:continue
      id=target.get('id');url=target.get('webSocketDebuggerUrl','');u=urllib.parse.urlsplit(url)
      if id in self.sockets or u.hostname not in ('127.0.0.1','localhost') or u.port!=self.port or not u.path.startswith('/devtools/page/'):continue
      ws=websocket.create_connection(url,timeout=.1,suppress_origin=True,http_proxy_host=None)
      self.sockets[id]=ws;self.attached+=1
      for n,method in enumerate(('Runtime.enable','Log.enable','Network.enable','Page.enable'),1):ws.send(json.dumps({'id':n,'method':method}))
    except Exception:pass
   if not self.sockets:self.stop.wait(.2)
   for id,ws in list(self.sockets.items()):
    try:
     data=ws.recv()
     if len(data)<262144:self.receive(json.loads(data))
    except websocket.WebSocketTimeoutException:pass
    except Exception:
     ws.close();del self.sockets[id]
  for ws in self.sockets.values():ws.close()
 def finish(self):
  self.stop.set();self.thread.join(timeout=5)
  return {'attached':self.attached,'events':self.events,'scope':'readonly CDP; no evaluation, body retrieval, interception or request changes'}
