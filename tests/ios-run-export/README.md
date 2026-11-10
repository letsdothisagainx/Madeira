# Run export native UI regression

This isolated simulator application compiles **the actual**
`app/Madeira/RunExportPresentation.swift`. It loads no Wine, Steam, game or
account data. The only supplied boundary is an asynchronous producer of a tiny,
valid ZIP. Streaming collection/compression has separate production tests.

The UI tests tap the real `RunExportButton` inside a SwiftUI menu. Cases cover
landscape presentation over a `normal + 101` controls window, destruction or
redraw of the originating menu while archive creation is suspended, native
**Save to Files** destination UI and its actual copy into the isolated host's
Documents folder, native cancellation, key-window restoration,
another export after the game controls end, and a useful native disk-full alert.
Both the archive handed to UIKit and the separate destination created by Apple's
Save to Files extension are opened with ZIP CRC and exact payload validation.
The host's archive producer only writes its temporary source; it cannot write
the destination that the collector requires. A genuine native activity callback
must report completion before window restoration and a second export are tested.
No mocked presenter can satisfy these positive tests.
These are simulator measurements using an owned fixture; they do not establish
that the user's complete run was saved or opened on the actual iPhone.

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
