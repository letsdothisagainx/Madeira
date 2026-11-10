# Run export native UI regression

This isolated simulator application compiles **the actual**
`app/Madeira/RunExportPresentation.swift`. It loads no Wine, Steam, game or
account data. The only supplied boundary is an asynchronous producer of a tiny,
valid ZIP. Streaming collection/compression has separate production tests.

The UI tests tap the real `RunExportButton` inside a SwiftUI menu. Cases cover
landscape presentation over a `normal + 101` controls window, destruction or
redraw of the originating menu while archive creation is suspended, native
**Save to Files** destination UI, native cancellation, key-window restoration,
another export after the game controls end, and a useful native disk-full alert.
The archive actually handed to UIKit is retained and opened with CRC validation.
No mocked presenter can satisfy these positive tests.
The Files picker is opened and cancelled; these tests do not claim that a file
has been saved or opened on the user's iPhone.

`fixtures/D6ExportViews.swift` contains the two literal D6 production views.
Their source revision and body digests are pinned in `fixtures/provenance.json`;
the generator additionally compares with Git objects when that commit exists.
Only the archive producer is supplied by the host. With its origin destroyed,
the old button-owned sheet must fail to appear after its archive is produced.
This is a controlled before/after UI regression, not proof of the exact failure
timing on the user's iPhone.

Run on the Apple CI runner using:

```sh
python3 tests/ios-run-export/run_simulator.py
```

The workflow requires an installed iPhone simulator and does not skip when one
is unavailable. It retains `.xcresult` and small owned fixture evidence. The
host bundle is `com.madeira.tests.RunExportUIHost`, distinct from Madeira.
Passing these tests does not replace installation and testing on the iPhone.
