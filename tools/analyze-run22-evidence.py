#!/usr/bin/env python3
"""Read-only Run22 replay; current namespace only. Never execute guest instructions."""
import argparse,hashlib,json,re,subprocess,sys,zipfile
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('archive');a=p.parse_args()
expected='ad3b677b0a54dcfe61dbb5e05676a6ed152ff32589956e03753fae4ae5351ef3'
with open(a.archive,'rb') as f:
 if hashlib.file_digest(f,'sha256').hexdigest()!=expected:raise SystemExit('not the supplied Run22 archive')
result=json.loads(subprocess.check_output([sys.executable,str(Path(__file__).with_name('analyze-run18-evidence.py')),a.archive,'--activation','2026-11-24T19:42:07Z','--close','2026-11-24T19:43:25Z','--process-lifetime','0x1030f0000-34']))
assert result['main']['count']==65 and result['main']['kernelSeconds']==30.587423
assert result['access']['alignedNoncrossingReleaseStores']==38
with zipfile.ZipFile(a.archive) as z:
 raw=z.read('sanitized/madeira-session.log').decode('utf-8')
 rows=[]
 for m in re.finditer(r'^\[xp\] (\d\d):(\d\d):(\d\d\.\d+) .*?dt=(\d+) .*?pgw=([\d.-]+)',raw,re.M):
  h,mi,sec,dt,wait=map(float,m.groups());end=h*3600+mi*60+sec
  if end-dt/1000>=14*3600+42*60+7 and end<=14*3600+43*60+25:rows.append((dt,wait))
 result['rawXPPageWait']={'scope':'whole-host-rusage Mach page-wait delta; not per-thread/per-file/CPU','clock':'original native local-wall timestamps UTC-05:00; dt rounded milliseconds; wholly-contained intervals','samples':len(rows),'elapsedSeconds':sum(r[0] for r in rows)/1000,'pageWaitSeconds':sum(r[1] for r in rows if r[1]>=0)/1000,'limits':'not subtracted from main CPU or treated as an explanation of all kernel time'}
print(json.dumps(result,indent=2))
