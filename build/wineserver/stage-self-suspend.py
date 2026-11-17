#!/usr/bin/env python3
"""Attach authoritative identity to successful suspend/resume replies.

The existing four padding bytes carry an internal identity tag; fixed packet
sizes, counts, physical holds, access checks and wakeup behavior remain intact.
"""
import argparse
from pathlib import Path


def stage(source: str) -> str:
    if 'ios_suspend_thread_reply' in source or 'ios_suspend_resume_observe' in source:
        raise ValueError('suspend identity is already staged')
    declaration = '''#ifdef WINE_IOS
extern void ios_suspend_thread_reply( struct thread *thread, void *padding, int operation );
extern void ios_suspend_resume_observe( struct thread *thread, int old_count );
#endif

'''
    anchor = '/* suspend a thread */\nDECL_HANDLER(suspend_thread)'
    if source.count(anchor) != 1:
        raise ValueError('suspend request declaration changed')
    for operation in ('suspend', 'resume'):
        anchor = f'''DECL_HANDLER({operation}_thread)
{{
    struct thread *thread;

    if ((thread = get_thread_from_handle( req->handle, THREAD_SUSPEND_RESUME )))
    {{
'''
        if source.count(anchor) != 1:
            raise ValueError(operation + ' request routing changed')
        start = source.index(anchor)
        end = source.index('\n}', start) + 2
        body = source[start:end]
        invocation = f'reply->count = {operation}_thread( thread );'
        if body.count(invocation) != 1 or body.count('        release_object( thread );') != 1:
            raise ValueError(operation + ' operation/lifetime changed')
        hook = """#ifdef WINE_IOS
        if (!get_error()) ios_suspend_thread_reply( thread, reply->__pad_12, OPERATION );
#endif
""".replace('OPERATION', '0' if operation == 'suspend' else '1')
        body = body.replace('        release_object( thread );', hook + '        release_object( thread );', 1)
        source = source[:start] + body + source[end:]
    anchor = '/* resume a thread */\nint resume_thread( struct thread *thread )'
    if source.count(anchor) != 1:
        raise ValueError('resume core declaration changed')
    start = source.index(anchor)
    end = source.index('\n}', start) + 2
    core = source[start:end]
    anchor = '    return old_count;'
    if core.count(anchor) != 1:
        raise ValueError('resume core result changed')
    core = core.replace(anchor, '''#ifdef WINE_IOS
    ios_suspend_resume_observe( thread, old_count );
#endif
''' + anchor, 1)
    source = source[:start] + core + source[end:]
    # Both declarations must precede the core resume function as well as the
    # request handlers. The server owns and references these objects here.
    anchor = '/* suspend a thread */\nint suspend_thread( struct thread *thread )'
    if source.count(anchor) != 1:
        raise ValueError('suspend core declaration changed')
    return source.replace(anchor, declaration + anchor, 1)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.source.resolve() == args.output.resolve():
        parser.error('pinned source must not be overwritten')
    staged = stage(args.source.read_text())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(staged)
    print('PASS staged authoritative suspend/resume identity; fixed packets and operation order preserved')
