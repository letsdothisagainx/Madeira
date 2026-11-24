#!/usr/bin/env python3
"""Normal event fixtures against actual queue/baseline; no Wine or device input."""
from pathlib import Path
import subprocess,tempfile,os,hashlib
r=Path(__file__).resolve().parents[2]
baseline=(r/'tests/fixtures/input-queue-482ac26f.h').read_bytes()
assert hashlib.sha256(baseline).hexdigest()=='6ac282f097fba6d84cacf3ae426dfed1682e6504da59d24ff7d1b0e9b6639f1f'
old=baseline.decode().replace('winios_input_event_t','baseline_event_t').replace('g_input_q','baseline_queue').replace('winios_q_push_ev','baseline_push')
with tempfile.TemporaryDirectory() as d:
 p=Path(d);(p/'input_queue_baseline.h').write_text(old)
 subprocess.run([os.getenv('CC','cc'),'-std=c11','-O2','-Wall','-Wextra','-Werror','-Wno-missing-field-initializers','-pthread','-I'+str(p),'-I'+str(r/'app/Madeira/Winios'),str(r/'tests/host/input_queue_test.c'),'-o',str(p/'check')],check=True)
 subprocess.run([str(p/'check')],check=True,timeout=10)
