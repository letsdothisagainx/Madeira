#!/usr/bin/env python3
"""Observe actual Windows process death without modifying pinned Wine sources."""
from pathlib import Path
import sys

def stage(source: str) -> str:
    marker = 'static void process_killed( struct process *process )\n{\n'
    assert source.count(marker) == 1, 'Wine process-death entry changed'
    hook = '''    /* Metadata-only callback: no server/guest call under the registry lock.
     * Last Windows thread death also covers exits from native worker threads. */
#ifdef WINE_IOS
    extern void ios_native_process_terminated(unsigned,unsigned) __attribute__((weak));
    if (ios_native_process_terminated) ios_native_process_terminated(process->id,process->exit_code);
    extern void madeira_child_server_exited(unsigned, int) __attribute__((weak));
    if (madeira_child_server_exited) madeira_child_server_exited(process->id, process->exit_code);
#endif
'''
    return source.replace(marker, marker + hook, 1)

if __name__ == '__main__':
    source, destination = map(Path, sys.argv[1:])
    text=source.read_text()
    if source.name == 'thread.c':
        marker='    thread->state = TERMINATED;'
        assert text.count(marker)==1
        hook='#ifdef WINE_IOS\n    { extern void ios_native_thread_terminated(unsigned long long,unsigned,unsigned,unsigned) __attribute__((weak));\n      if (ios_native_thread_terminated) ios_native_thread_terminated(thread->teb,thread->process->id,thread->id,thread->exit_code); }\n#endif\n'
        text=text.replace(marker,hook+marker,1)
    else: text=stage(text)
    destination.write_text(text)
