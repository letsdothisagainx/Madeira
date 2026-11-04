"""Read-only loopback CEF event observer for a fresh unauthenticated fixture."""
import json,re,threading,time,urllib.parse,urllib.request
# No Steam APIs are invoked. Descriptors are inspected without reading getters.
SNAPSHOT_JS=r'''(()=>{const names=o=>{try{return Object.getOwnPropertyNames(o).slice(0,100)}catch(e){return ['[unavailable]']}};let client=typeof SteamClient==='undefined'?null:SteamClient;let shape={};if(client){for(const key of names(client)){try{let d=Object.getOwnPropertyDescriptor(client,key);shape[key]=!d?'missing':('value'in d?(d.value===null?'null':typeof d.value):'accessor');if(d&&'value'in d&&d.value&&typeof d.value==='object')shape[key]={kind:'object',names:names(d.value)};}catch(e){shape[key]='[unavailable]'}}}return {ready:document.readyState,url:location.href,title:document.title,body:document.body?document.body.innerText.slice(0,900):'',elements:document.getElementsByTagName('*').length,scripts:Array.from(document.scripts).slice(0,24).map(s=>s.src),steamClientType:typeof SteamClient,steamClientShape:shape}})()'''
class Observer:
 def __init__(self,port):
  self.port=port;self.stop=threading.Event();self.events=[];self.attached=0;self.requests={};self.sockets={};self.pending={};self.sequence=100;self.snapshots={};self.targets={};self.received=0;self.started=time.monotonic()
  self.thread=threading.Thread(target=self.run,daemon=True);self.thread.start()
 def url(self,value):
  try:
   u=urllib.parse.urlsplit(value)
   if u.username or u.password:return '[private-url]'
   host=(u.hostname or '').lower()
   if host not in ('steamloopback.host','localhost','127.0.0.1') and not host.endswith(('.steampowered.com','.steamstatic.com','.steamcommunity.com')):return '[external-origin]'
   path=re.sub(r'[A-Za-z0-9_-]{48,}','[opaque]',u.path)[:240]
   return (u.scheme+'://'+host+path)[:320]
  except Exception:return '[url]'
 def message(self,value):
  if not isinstance(value,str):return ''
  value=re.sub(r'(?:https?|wss?)://[^\s\"<>]+',lambda m:self.url(m[0]),value)
  value=re.sub(r'(?i)(authorization|cookie|password|ticket|access_token|refresh_token|sessionid|steamid)\s*[:=]\s*[^\s,;]+',r'\1=[redacted]',value)
  value=re.sub(r'[A-Za-z0-9_+/=-]{48,}','[opaque]',value)
  return ''.join(c for c in value if c=='\n' or ord(c)>=32)[:900]
 def add(self,event):
  if len(self.events)<100:self.events.append({'seconds':round(time.monotonic()-self.started,2),**event})
 def sanitized_snapshot(self,data):
  if not isinstance(data,dict):return {}
  out={key:self.message(data.get(key,'')) for key in ('ready','title','body','steamClientType')}
  out['url']=self.url(data.get('url',''));out['elements']=data.get('elements',0)
  out['scripts']=[self.url(v) for v in data.get('scripts',[])[:24]]
  shape=data.get('steamClientShape',{})
  out['steamClientShape']={self.message(k):({'kind':'object','names':[self.message(n) for n in v.get('names',[])[:100]]} if isinstance(v,dict) else self.message(v)) for k,v in list(shape.items())[:100]} if isinstance(shape,dict) else {}
  return out
 def resources(self,node,out):
  if not isinstance(node,dict) or len(out)>=32:return
  frame=node.get('frame',{})
  if frame:out.append({'kind':'frame','url':self.url(frame.get('url','')),'mime':frame.get('mimeType','')})
  for resource in node.get('resources',[]):
   if len(out)>=32:break
   out.append({'kind':'resource','url':self.url(resource.get('url','')),'type':resource.get('type',''),'mime':resource.get('mimeType','')})
  for child in node.get('childFrames',[]):self.resources(child,out)
 def receive(self,payload,target):
  if 'id'in payload:
   request=self.pending.pop((target,payload['id']),None)
   if request:
    if 'error'in payload:self.add({'kind':'snapshot-error','target':self.targets.get(target,''),'method':request,'error':self.message(str(payload['error']))})
    elif request=='Runtime.evaluate':
     result=payload.get('result',{}).get('result',{}).get('value',{})
     self.add({'kind':'snapshot','target':self.targets.get(target,''),**self.sanitized_snapshot(result)})
    elif request=='Page.getResourceTree':
     rows=[];self.resources(payload.get('result',{}).get('frameTree',{}),rows)
     self.add({'kind':'resource-tree','target':self.targets.get(target,''),'resources':rows})
   return
  method=payload.get('method','');p=payload.get('params',{})
  if method=='Network.requestWillBeSent':
   if len(self.requests)<2048:self.requests[(target,p.get('requestId',''))]={'url':self.url(p.get('request',{}).get('url','')),'type':p.get('type','')}
  elif method=='Network.responseReceived':
   response=p.get('response',{});status=response.get('status',0)
   if status>=400:self.add({'kind':'response','url':self.url(response.get('url','')),'status':status,'type':p.get('type','')})
  elif method=='Network.loadingFailed':
   row=self.requests.get((target,p.get('requestId','')),{});self.add({'kind':'loading-failed',**row,'error':self.message(p.get('errorText','')),'cancelled':p.get('canceled',False)})
  elif method=='Runtime.exceptionThrown':
   d=p.get('exceptionDetails',{});e=d.get('exception',{})
   self.add({'kind':'exception','text':self.message(e.get('description') or d.get('text','')),'url':self.url(d.get('url','')),'line':d.get('lineNumber',0),'frames':[{'function':self.message(f.get('functionName','')),'url':self.url(f.get('url','')),'line':f.get('lineNumber',0),'column':f.get('columnNumber',0)} for f in d.get('stackTrace',{}).get('callFrames',[])[:8]]})
  elif method=='Runtime.consoleAPICalled' and p.get('type') in ('error','warning','warn'):
   text=' '.join((a.get('value','') if a.get('type')=='string' else a.get('description','')) for a in p.get('args',[]) if isinstance(a.get('value',''),str));self.add({'kind':'console','level':p.get('type'),'text':self.message(text)})
  elif method=='Log.entryAdded':
   e=p.get('entry',{})
   if e.get('level') in ('error','warning'):self.add({'kind':'log','source':e.get('source'),'level':e.get('level'),'text':self.message(e.get('text','')),'url':self.url(e.get('url',''))})
 def send_snapshot(self,target,ws):
  for method,params in (('Runtime.evaluate',{'expression':SNAPSHOT_JS,'returnByValue':True,'silent':True}),('Page.getResourceTree',{})):
   self.sequence+=1;self.pending[(target,self.sequence)]=method;ws.send(json.dumps({'id':self.sequence,'method':method,'params':params}))
 def run(self):
  import websocket
  next_discover=0
  while not self.stop.is_set():
   now=time.monotonic()
   if now>=next_discover:
    next_discover=now+1
    try:
     with urllib.request.urlopen('http://127.0.0.1:'+str(self.port)+'/json/list',timeout=.5) as r:targets=json.loads(r.read(262144))
     for target in targets:
      if target.get('type')!='page' or len(self.sockets)>=8:continue
      id=target.get('id');url=target.get('webSocketDebuggerUrl','');u=urllib.parse.urlsplit(url)
      if id in self.sockets or u.hostname not in ('127.0.0.1','localhost') or u.port!=self.port or not u.path.startswith('/devtools/page/'):continue
      ws=websocket.create_connection(url,timeout=.005,suppress_origin=True,http_proxy_host=None)
      self.sockets[id]=ws;self.attached+=1;self.targets[id]=self.url(target.get('url',''));self.snapshots[id]=[now,0]
      self.add({'kind':'target','url':self.targets[id],'type':'page'})
      for n,method in enumerate(('Runtime.enable','Log.enable','Network.enable','Page.enable'),1):ws.send(json.dumps({'id':n,'method':method}))
    except Exception:pass
   if not self.sockets:self.stop.wait(.2)
   for id,ws in list(self.sockets.items()):
    try:
     start,number=self.snapshots[id];delays=(0,3,15,45,90,140)
     if number<len(delays) and now-start>=delays[number]:self.send_snapshot(id,ws);self.snapshots[id][1]+=1
     # Drain each ready page before waiting on another. A blocking receive
     # per idle page otherwise throttles another page's Network event backlog.
     for _ in range(512):
      data=ws.recv();self.received+=1
      if len(data)<262144:self.receive(json.loads(data),id)
    except websocket.WebSocketTimeoutException:pass
    except Exception:
     ws.close();del self.sockets[id]
  for ws in self.sockets.values():ws.close()
 def finish(self):
  self.stop.set();self.thread.join(timeout=5)
  return {'attached':self.attached,'received':self.received,'events':self.events,'scope':'readonly CDP; passive DOM/API descriptors only in fresh unauthenticated fixture; no Steam API calls, interception or request changes'}
