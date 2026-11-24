    func incident(_ reason:String) {
        let priority=reason.contains("disconnect") || reason.contains("guest-process-exit") ? 4 : reason.contains("texture") || reason.contains("resource") ? 3 : 1
        let now=RunEvidenceSchema.mono()
        if priority<incidentPriority || (priority==incidentPriority && lastIncidentNS>0 && now>=lastIncidentNS && now-lastIncidentNS<10_000_000_000) {suppressedIncidents+=1;return}
        incidentPriority=priority;lastIncidentNS=now
        let begin=now;incidentCount+=1;defer{incidentNS+=RunEvidenceSchema.mono()-begin}
        record("timeline",["event":"incident-window","reason":reason,"priority":priority])
        func capture(_ name:String,focused:Bool=false) {
            let url=directory.appendingPathComponent(name);try? fm.removeItem(at:url)
            let fd=open(url.path,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0o600)
            guard fd>=0 else{writeFailures+=1;return};defer{close(fd)}
            let ordinary=[("resource-failures",192<<10),("input-path",64<<10),("timeline",128<<10),("thread-frame-memory",256<<10),("memory-access",256<<10),("vm-operations",64<<10),("graphics-errors",64<<10)]
            let budgets=focused ? [("timeline",32<<10),("thread-frame-memory",128<<10),("memory-access",64<<10),("vm-operations",16<<10),("input-path",16<<10)] : ordinary
            for(channel,maximum) in budgets {
                guard let f=files[channel] else{continue}
                let copied=Self.copy(directory.appendingPathComponent("\(channel).\(f.slot).jsonl"),to:fd,maximum:maximum,tail:true)
                logicalBytes+=UInt64(copied);incidentBytes+=UInt64(copied)
            }
        }
        if reason=="post-activation-frame-stall" && !firstPostActivationStallSaved {capture("incident-post-activation-first.jsonl",focused:true);firstPostActivationStallSaved=true}
        if priority>=3 && !firstIncidentSaved {capture("incident-first.jsonl");firstIncidentSaved=true}
        capture("incident.jsonl")
    }
