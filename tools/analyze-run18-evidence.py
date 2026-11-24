#!/usr/bin/env python3
"""Read-only, clock-correlated analysis of an exported run; no guest execution.
Only current evidence members are read. Incident duplicates use (runID, sequence).
"""
import argparse,json,zipfile,datetime,collections,hashlib
p=argparse.ArgumentParser();p.add_argument('zip');p.add_argument('--activation',required=True);p.add_argument('--close',required=True);p.add_argument('--process-lifetime');p.add_argument('--io-start-sequence');p.add_argument('--io-end-sequence');a=p.parse_args()
with zipfile.ZipFile(a.zip) as z:
    def read(name):
        info=z.getinfo(name)
        if info.file_size>32<<20:raise ValueError('member too large: '+name)
        return z.read(name)
    summary=json.loads(read('evidence/run-summary.json'));run=summary['runID'];rows={};conflicts=0;duplicates=0
    for name in z.namelist():
        if not name.startswith('evidence/') or name.count('/')!=1 or not name.endswith('.jsonl'):continue
        for line in read(name).splitlines():
            r=json.loads(line)
            if r.get('runID')!=run or 'sequence' not in r:continue
            key=(run,r['sequence'])
            if key in rows:
                duplicates+=1;conflicts+=rows[key]!=r
            else:rows[key]=r
rows=list(rows.values());anchors=[r for r in rows if r.get('event')=='clock-calibration']
def wall(ns):
    c=min(anchors,key=lambda c:abs((int(c['monotonicBeforeNS'])+int(c['monotonicAfterNS']))/2-ns))
    return c['wallUnixSeconds']+(ns-(int(c['monotonicBeforeNS'])+int(c['monotonicAfterNS']))/2)/1e9
start=datetime.datetime.fromisoformat(a.activation.replace('Z','+00:00')).timestamp();end=datetime.datetime.fromisoformat(a.close.replace('Z','+00:00')).timestamp()
def instant(r):return wall(int(r.get('registerCaptureBeginNS') or r.get('nativeMonotonicNS') or r['receivedMonotonicNS']))
lifetimes={r.get('processLifetimeID') for r in rows if r.get('event')=='main-progress' and start<=instant(r)<=end}
lifetime=a.process_lifetime or (next(iter(lifetimes)) if len(lifetimes)==1 else None)
if not lifetime:raise ValueError('ambiguous lifetime; supply --process-lifetime')
main=[r for r in rows if r.get('processLifetimeID')==lifetime and r.get('event')=='main-progress' and instant(r)<=end and instant(r)-r['intervalUS']/1e6>=start]
access=[r for r in rows if r.get('processLifetimeID')==lifetime and r.get('event')=='sampled-access-mapping' and start<=instant(r)<=end]
user=sum(r['userCPUUS'] for r in main);kernel=sum(r['kernelCPUUS'] for r in main)
io=[r for r in rows if r.get('event')=='paging-IO-progress' and r.get('result')==0 and start<=instant(r)<=end];io.sort(key=instant)
if a.io_start_sequence:io[0]=next(r for r in rows if r['sequence']==a.io_start_sequence)
if a.io_end_sequence:io[-1]=next(r for r in rows if r['sequence']==a.io_end_sequence)
slow=[r for r in rows if r.get('event')=='VM-slow-or-error' and start<=instant(r)<=end]
io.sort(key=instant)
if bool(a.io_start_sequence)!=bool(a.io_end_sequence):raise ValueError('both I/O sequence boundaries required')
if a.io_start_sequence:
    io=[next(r for r in io if r['sequence']==v) for v in [a.io_start_sequence,a.io_end_sequence]]
print(json.dumps({'runID':run,'processLifetimeID':lifetime,'deduplicatedRecords':len(rows),'incidentDuplicatesRemoved':duplicates,'inconsistentDuplicateRows':conflicts,
 'selection':'main interval [captureNS - intervalUS*1000, captureNS] wholly within original console activation/explicit-close wall window; nearest measured calibration; no parser-arrival phase selection; no previous native session',
 'clockUncertainty':'console whole-second boundaries plus calibration uncertainty; sample/query are post-resume and not atomic; not packet-arrival times',
 'main':{'count':len(main),'intervalSeconds':sum(r['intervalUS'] for r in main)/1e6,'userSeconds':user/1e6,'kernelSeconds':kernel/1e6,'kernelFractionOfConsumedCPU':kernel/(user+kernel) if user+kernel else None},
 'access':{'count':len(access),'backingLedger':sum(r['backing']=='Madeira-backing-ledger' for r in access),'alignedNoncrossingReleaseStores':sum(r['backing']=='Madeira-backing-ledger' and r['accessType']=='store-release' and r['alignmentRemainder']==0 and not r['crossesHostPage'] for r in access),'crossingOrdinaryStores':sum(r['accessType']=='store' and r['crossesHostPage'] for r in access)},
 'pagingIO':{'scope':'whole-host-app proc_pid_rusage; not per-thread/per-file/storage wear','firstSequence':io[0]['sequence'],'lastSequence':io[-1]['sequence'],'elapsedSeconds':instant(io[-1])-instant(io[0]),'writeBytes':io[-1]['writeBytesCumulative']-io[0]['writeBytesCumulative'],'readBytes':io[-1]['readBytesCumulative']-io[0]['readBytesCumulative'],'pageIns':io[-1]['pageInsCumulative']-io[0]['pageInsCumulative']},
 'retainedSlowVM':{'count':len(slow),'byOperation':dict(collections.Counter(r['operation'] for r in slow)),'maxDurationNS':max((r['durationNS'] for r in slow),default=None),'coverage':'instrumented retained completions only; try-lock drops and uninstrumented kernel work remain'}},indent=2))
