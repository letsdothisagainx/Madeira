#!/usr/bin/env python3
"""Observe original CS2 window geometry in an owned, immutable-input Wine copy."""
import argparse
import hashlib
import json
from pathlib import Path
import tempfile


def stage(source):
    if 'window_geometry.h' in source or 'madeira_window_geometry_' in source:
        raise ValueError('window geometry input is already staged')
    signature = 'HWND WINAPI NtUserCreateWindowEx('
    if source.count(signature) != 1:
        raise ValueError('CreateWindowEx function contract changed')
    begin = source.index(signature)
    end = source.index('\n}\n', begin) + 2
    part = source[begin:end]

    def splice(anchor, addition, before=False):
        nonlocal part
        if part.count(anchor) != 1:
            raise ValueError('CreateWindowEx splice contract changed: ' + anchor[:80])
        part = part.replace(anchor, addition + anchor if before else anchor + addition)

    splice('    WND *win;\n', '''    struct madeira_window_geometry md_geometry = madeira_window_geometry_begin(
        style, ex_style, x, y, cx, cy, parent);
''')
    splice('    fix_cs_coordinates( &cs, &sw );',
           '\n    madeira_window_geometry_defaults( &md_geometry, &cs );')
    splice('    win_dpi = get_dpi_for_window( hwnd );',
           '\n    if (md_geometry.sequence) md_geometry.window_dpi = win_dpi;')
    splice('    surface = get_window_surface( hwnd, SWP_NOZORDER | SWP_NOACTIVATE, FALSE, &new_rects, &surface_rect );',
           '    madeira_window_geometry_rects( &md_geometry, &new_rects, 0 );\n', before=True)
    splice('        map_window_points( 0, parent, (POINT *)&new_rects.client, 2, win_dpi );',
           '\n        madeira_window_geometry_rects( &md_geometry, &new_rects, 1 );')
    if part.count('return 0;') != 7 or part.count('return hwnd;') != 1:
        raise ValueError('CreateWindowEx return contract changed')
    part = part.replace('return 0;', 'return madeira_window_geometry_result( &md_geometry, 0 );')
    part = part.replace('return hwnd;', 'return madeira_window_geometry_result( &md_geometry, hwnd );')
    output = source[:begin] + part + source[end:]
    anchor = 'WINE_DEFAULT_DEBUG_CHANNEL(win);'
    if output.count(anchor) != 1:
        raise ValueError('window include contract changed')
    return output.replace(anchor, '#include "window_geometry.h"\n\n' + anchor)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.source.resolve() == args.output.resolve():
        parser.error('input must remain immutable; output must be an owned build copy')
    original = args.source.read_bytes()
    output = stage(original.decode()).encode()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=args.output.parent, delete=False) as temp:
        temp.write(output)
        temporary = Path(temp.name)
    temporary.replace(args.output)
    print(json.dumps({'stage': 'cs2-window-geometry-v1', 'source_sha256': hashlib.sha256(original).hexdigest(),
                      'output_sha256': hashlib.sha256(output).hexdigest(), 'geometry_changes': False,
                      'records_per_process': 32, 'process_slots': 32}))


if __name__ == '__main__':
    main()
