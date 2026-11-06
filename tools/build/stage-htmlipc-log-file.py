#!/usr/bin/env python3
"""Stage the cached helper's exact private logger path without changing Wine."""
from pathlib import Path
import sys
source = Path(sys.argv[1])
text = source.read_text()
header = Path(__file__).resolve().parents[2] / 'build/ntdll-unix/htmlipc_log_file.h'
include = '#include "unix_private.h"'
assert text.count(include) == 1
text = text.replace(include, include + '\n#include "' + str(header) + '"')
start = text.index('NTSTATUS WINAPI NtCreateFile(')
end = text.index('\nNTSTATUS WINAPI NtOpenFile(', start)
block = text[start:end]
old = '    OBJECT_ATTRIBUTES new_attr;'
assert block.count(old) == 1
block = block.replace(old, old + '''
    WCHAR htmlipc_log_path[128];
    UNICODE_STRING htmlipc_log_name;
    BOOL htmlipc_log_redirected = FALSE;''')
old = '    new_attr = *attr;'
assert block.count(old) == 1
block = block.replace(old, old + '''
    /* The executable's own base logger opens <module-dir>/debug.log even
     * with CEF --log-file. Keep only that mutable file outside verified data. */
    if (!new_attr.RootDirectory && !(options & (FILE_OPEN_BY_FILE_ID | FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT)) &&
        madeira_htmlipc_default_log_candidate(new_attr.ObjectName->Buffer, new_attr.ObjectName->Length / sizeof(WCHAR),
                                              getenv("MADEIRA_HTMLIPC_CACHE_DIR")))
    {
        TEB *teb = NtCurrentTeb();
        RTL_USER_PROCESS_PARAMETERS *params = teb && teb->Peb ? teb->Peb->ProcessParameters : NULL;
        size_t length;
        if (params && new_attr.ObjectName && !(new_attr.ObjectName->Length & 1) &&
            !(params->ImagePathName.Length & 1) &&
            madeira_htmlipc_default_log(new_attr.ObjectName->Buffer, new_attr.ObjectName->Length / sizeof(WCHAR),
                params->ImagePathName.Buffer, params->ImagePathName.Length / sizeof(WCHAR),
                getenv("MADEIRA_HTMLIPC_HELPER"), getenv("MADEIRA_HTMLIPC_CACHE_DIR"),
                htmlipc_log_path, ARRAY_SIZE(htmlipc_log_path), &length))
        {
            htmlipc_log_name.Buffer = htmlipc_log_path;
            htmlipc_log_name.Length = length * sizeof(WCHAR);
            htmlipc_log_name.MaximumLength = (length + 1) * sizeof(WCHAR);
            new_attr.ObjectName = &htmlipc_log_name;
            htmlipc_log_redirected = TRUE;
        }
        else
        {
            static unsigned int declined;
            if (__atomic_fetch_add(&declined, 1u, __ATOMIC_RELAXED) < 4)
                dprintf(2, "[htmlipc-log-file-v1] destination=unchanged result=declined reason=image-context\\n");
        }
    }''')
old = '    if (status == STATUS_BAD_DEVICE_TYPE)'
assert block.count(old) == 1
block = block.replace(old, '''    if (htmlipc_log_redirected)
    {
        static unsigned int reports;
        if ((status == STATUS_SUCCESS || status == STATUS_NO_SUCH_FILE) &&
            !madeira_htmlipc_mutable_log_owned(unix_name)) status = STATUS_ACCESS_DENIED;
        if (__atomic_fetch_add(&reports, 1u, __ATOMIC_RELAXED) < 8)
            dprintf(2, "[htmlipc-log-file-v1] destination=owned-mutable result=%s status=%08x\\n",
                status == STATUS_SUCCESS || status == STATUS_NO_SUCH_FILE ? "routed" : "unavailable", status);
    }

''' + old)
text = text[:start] + block + text[end:]
source.write_text(text)
