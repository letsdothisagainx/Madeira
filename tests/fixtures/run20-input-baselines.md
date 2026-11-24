# Run20 normal-input baseline excerpts

`input-queue-482ac26f.h` contains the input transport types and exact
`winios_q_push_ev` body from `app/Madeira/Winios/Winios.m` at
`482ac26ffb81a2985310d64c697c61616f5134ed`.
`pad-kbm-482ac26f.swift` contains the exact `PadKeyboardMouse` class at that
same revision. Tests verify fixed SHA-256 identities, rename symbols solely
for side-by-side compilation, and use ordinary in-memory events and metadata
adapters. They do not depend on repository history in a shallow CI checkout.
No captured instruction, device injection or fault scenario is executed.
