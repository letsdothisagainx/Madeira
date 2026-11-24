#!/usr/bin/env python3
"""Normal event fixtures against actual queue/baseline; no Wine or device input."""
from pathlib import Path
import subprocess,tempfile,os
r=Path(__file__).resolve().parents[2]
baseline=subprocess.check_output(['git','show','482ac26f:app/Madeira/Winios/Winios.m'],cwd=r,text=True)
types=baseline[baseline.index('#define WINIOS_RING_SIZE 256'):baseline.index('static _Atomic unsigned int g_text_generation;')]
a=baseline.index('static void winios_q_push_ev(');b=baseline.index('\n}',a)+2
old=(types+baseline[a:b]).replace('winios_input_event_t','baseline_event_t').replace('g_input_q','baseline_queue').replace('winios_q_push_ev','baseline_push')
with tempfile.TemporaryDirectory() as d:
 p=Path(d);(p/'input_queue_baseline.h').write_text(old)
 subprocess.run([os.getenv('CC','cc'),'-std=c11','-O2','-Wall','-Wextra','-Werror','-Wno-missing-field-initializers','-pthread','-I'+str(p),'-I'+str(r/'app/Madeira/Winios'),str(r/'tests/host/input_queue_test.c'),'-o',str(p/'check')],check=True)
 subprocess.run([str(p/'check')],check=True,timeout=10)
