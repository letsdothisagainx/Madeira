#!/usr/bin/env python3
"""Bind the rebuilt LFH size function to the stripped native ntdll image.

The check uses the real heap.o function and its relocation mask, then resolves
the final PE export through ARM64EC native redirections. No runtime marker or
new export is needed. build-ntdll.sh rebuilds heap.o from the staged source.
"""
import argparse
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("native_code", ROOT / "tools/check-native-srw-code.py")
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)
spec = importlib.util.spec_from_file_location("lfh_size_source", ROOT / "tools/build/stage-native-lfh-size.py")
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)
FUNCTION = "RtlSizeHeap"


def check(image, obj, machine, source):
    farm = {"aarch64": "aarch64-windows", "arm64ec": "arm64ec-windows"}[machine]
    data, original = native.code.read(image), native.code.read(obj, 32 << 20)
    compiled = native.code.Code(original)
    allowed = {0xaa64} if machine == "aarch64" else {0xaa64, 0xa641}
    assert not compiled.pe and compiled.machine in allowed, "wrong native LFH size object architecture"
    proof = compiled.proof(compiled.function(FUNCTION))
    actual = native.Image(data, farm, required_export=FUNCTION)
    target = actual.native_target(machine)
    wanted, mask = bytes.fromhex(proof["code"]), bytes.fromhex(proof["mask"])
    linked = actual.read(target, len(wanted), executable=True)
    assert bytes(a & b for a, b in zip(linked, mask)) == wanted, "packaged LFH size code differs from rebuilt heap.o"
    text = native.code.read(source, 2 << 20).decode()
    start = text.index(stage.SIGNATURE)
    body = text[start:text.index("\n}\n", start) + 3]
    assert body.count(stage.FAST) == 1, "compiled heap source lacks the complete conservative LFH guard"
    assert body.count(stage.ANCHOR) == 1, "compiled heap source changed the serialized fallback"
    # Removing the one owned addition must reconstruct an accepted original
    # function. This also rejects duplicate or unrecognized source edits.
    restored = text[:start] + body.replace(stage.FAST, "", 1) + text[start + len(body):]
    assert stage.stage(restored) == text, "LFH source guard/fallback cannot be reconstructed exactly"
    result = {"machine": machine, "native_rva": target, "bytes": len(wanted),
              "object_sha256": native.code.digest(original),
              "masked_code_sha256": native.code.digest(wanted),
              "stage_sha256": native.code.digest(native.code.read(ROOT / "tools/build/stage-native-lfh-size.py", 1 << 20))}
    print("PASS native LFH size compiled-object -> stripped PE export/native entry: " + str(result))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--object", type=Path, required=True)
    parser.add_argument("--machine", choices=("aarch64", "arm64ec"), required=True)
    parser.add_argument("--source-heap", type=Path, required=True)
    args = parser.parse_args()
    check(args.image, args.object, args.machine, args.source_heap)
