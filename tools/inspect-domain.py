#!/usr/bin/env python3
"""Read-only bounded PE evidence for domain mapping; never imports/executes PE.
Run against pinned local extracted images. All RVAs are relative to that image.
"""
import argparse, base64, bisect, hashlib, json, re, struct, zlib
from pathlib import Path
import capstone, pefile

DOMAIN_WRAPPER = '.?AV?$CHTMLProtoBufMsg@VCMsgSetBrowserViewDomainRequestMapping@@@@'
LOCAL_WRAPPER = '.?AV?$CHTMLProtoBufMsg@VCMsgSetLocalFileRequestMapping@@@@'
TERMS = ('BrowserViewDomain', 'LocalFileRequest', 'steamloopback', 'localhost',
         'RequestMapping', 'SchemeHandlerFactory', 'local file', 'request domain')
MAX_TOTAL_BYTES = 2 << 20
MAX_FUNCTION_BYTES = 128 << 10

class Inspector:
    def __init__(self, path, expected):
        self.raw = Path(path).read_bytes()
        digest = hashlib.sha256(self.raw).hexdigest()
        if expected and digest != expected:
            raise ValueError(('image pin mismatch', path, expected, digest))
        self.pe = pefile.PE(data=self.raw)
        if self.pe.FILE_HEADER.Machine != 0x8664:
            raise ValueError('This inspector expects AMD64 image and unwind metadata')
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.size = self.pe.OPTIONAL_HEADER.SizeOfImage
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.md.detail = True
        self.md.skipdata = True
        self.functions = sorted((e.struct.BeginAddress, e.struct.EndAddress)
                                for e in self.pe.DIRECTORY_ENTRY_EXCEPTION)
        self.starts = [a for a, b in self.functions]
        self.execs = [(s.VirtualAddress, s.get_data()) for s in self.pe.sections
                      if s.Characteristics & 0x20000000]
        self.imports = {i.address-self.base: e.dll.decode(errors='replace')+'!'+
                        (i.name.decode(errors='replace') if i.name else '#'+str(i.ordinal))
                        for e in getattr(self.pe, 'DIRECTORY_ENTRY_IMPORT', []) for i in e.imports}
        self.strings = {}
        for m in re.finditer(rb'[\x20-\x7e]{5,350}', self.raw):
            try: rva = self.pe.get_rva_from_offset(m.start())
            except pefile.PEFormatError: continue
            self.strings[rva] = m[0].decode()
        self.result = dict(path=str(path), sha256=digest, machine='AMD64',
                           image_base=hex(self.base), image_size=hex(self.size),
                           strings={}, vtables=[], target_xrefs=[],
                           functions={}, global_xrefs=[], slot38_candidates=[])
        self.used = 0

    def data(self, rva, size):
        if rva < 0 or size < 0 or rva+size > self.size: return b''
        return self.pe.get_data(rva, size)

    def function(self, rva):
        n = bisect.bisect_right(self.starts, rva)-1
        if n >= 0 and rva < self.functions[n][1]: return self.functions[n]
        return rva, min(rva+256, self.size)

    def executable(self, rva):
        return any(a <= rva < a+len(b) for a, b in self.execs)

    def instruction(self, ins):
        row = dict(rva=hex(ins.address), bytes=ins.bytes.hex(), asm=ins.mnemonic+' '+ins.op_str)
        refs = []
        for op in ([] if ins.id == 0 else ins.operands):
            if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                target = ins.address+ins.size+op.mem.disp
                ref = {'rva': hex(target)}
                if target in self.strings: ref['literal'] = self.strings[target]
                elif target in self.imports: ref['import'] = self.imports[target]
                else:
                    b = self.data(target, 64)
                    if b: ref['bytes64'] = b.hex()
                refs.append(ref)
        if refs: row['refs'] = refs
        return row

    def capture(self, rva, reason, explicit_end=None, follow=False):
        if not self.executable(rva): return
        a, z = self.function(rva)
        if explicit_end is not None: a, z = rva, explicit_end
        key = hex(a)
        if key in self.result['functions']:
            self.result['functions'][key]['reasons'].append(reason)
            return
        if self.used >= MAX_TOTAL_BYTES: return
        end = min(z, a+MAX_FUNCTION_BYTES, a+MAX_TOTAL_BYTES-self.used)
        raw = self.data(a, end-a)
        instructions = list(self.md.disasm(raw, a))
        self.used += len(raw)
        self.result['functions'][key] = dict(start=hex(a), end=hex(z),
            captured_end=hex(end), complete=end == z, reasons=[reason], raw=raw.hex(),
            instructions=[self.instruction(i) for i in instructions])
        if follow:
            for ins in instructions:
                if ins.id != 0 and ins.mnemonic == 'call' and ins.operands[0].type == capstone.x86.X86_OP_IMM:
                    target = ins.operands[0].imm
                    if self.executable(target): self.capture(target, 'direct call from '+key)

    def tables(self):
        wanted = {r-16:s for r,s in self.strings.items()
                  if s in (DOMAIN_WRAPPER, LOCAL_WRAPPER)}
        for section in self.pe.sections:
            if section.Characteristics & 0x20000000: continue
            data, start = section.get_data(), section.VirtualAddress
            for pos in range(0, len(data)-24, 4):
                signature, off, cd, typ, hierarchy, self_rva = struct.unpack_from('<6I', data, pos)
                col = start+pos
                if signature != 1 or self_rva != col or typ not in wanted: continue
                ptr = struct.pack('<Q', self.base+col)
                for other in self.pe.sections:
                    other_data = other.get_data()
                    for m in re.finditer(re.escape(ptr), other_data):
                        vtable = other.VirtualAddress+m.start()+8
                        entries = []
                        for n in range(24):
                            b = self.data(vtable+8*n, 8)
                            if len(b) != 8: break
                            fn = struct.unpack('<Q', b)[0]-self.base
                            if not self.executable(fn): break
                            entries.append(hex(fn))
                        if entries:
                            self.result['vtables'].append(dict(rva=hex(vtable), col=hex(col),
                                type=wanted[typ], offset=off, entries=entries))

    def rip_xrefs(self, targets, globals_):
        # Byte candidates are decoded and verified as RIP-relative instructions.
        # Capturing their enclosing function lets a reviewer verify boundaries.
        all_targets = targets | globals_
        pattern = re.compile(rb'[\x40-\x4f][\x8b\x89\x8d][\x05\x0d\x15\x1d\x25\x2d\x35\x3d]....', re.S)
        for start, data in self.execs:
            for m in pattern.finditer(data):
                target = start+m.start()+7+struct.unpack_from('<i', m[0], 3)[0]
                if target not in all_targets: continue
                ins = next(self.md.disasm(m[0], start+m.start(), count=1), None)
                if not ins or ins.size != 7: continue
                row = self.instruction(ins)
                row['function'] = [hex(x) for x in self.function(ins.address)]
                if target in globals_:
                    self.result['global_xrefs'].append(row)
                    self.capture(ins.address, 'actual controller global reference')
                else:
                    self.result['target_xrefs'].append(row)
                    self.capture(ins.address, 'mapping wrapper/string reference')
                    # The dispatcher can be one large switch. Follow only the
                    # small call region around this constructor, preserving
                    # budget for the actual handler rather than unrelated cases.
                    lo, hi = self.function(ins.address)
                    lo, hi = max(lo,ins.address-128), min(hi,ins.address+1536)
                    for call in self.md.disasm(self.data(lo,hi-lo),lo):
                        if call.mnemonic == 'call' and call.operands[0].type == capstone.x86.X86_OP_IMM:
                            self.capture(call.operands[0].imm, 'mapping-nearby direct target')

    def inspect(self, label):
        self.tables()
        extra = {'current-steamui': [(0x200390,0x201200),(0xaaece0,0xaaefe0)], 'legacy-steamui': [(0x1d4cc0,0x1d6100),(0xa40190,0xa40490)]}
        for a,z in extra.get(label,[]): self.capture(a,'explicit response ABI boundary',z,True)
        literals = {r:s for r,s in self.strings.items()
                    if any(t.lower() in s.lower() for t in TERMS)}
        self.result['strings'] = {hex(r):s for r,s in literals.items()}
        targets = set(literals) | {int(v['rva'],16) for v in self.result['vtables']}
        globals_ = {0x11935b8} if label == 'current-steamui' else set()
        if globals_: self.rip_xrefs(set(), globals_)
        wrapper_targets = {int(v['rva'],16) for v in self.result['vtables']}
        self.rip_xrefs(wrapper_targets, set())
        self.rip_xrefs(targets-wrapper_targets, set())
        if label == 'current-steamui':
            # Split unwind regions otherwise hide the controller-init continuation.
            self.capture(0x594db0, 'explicit complete controller initialization region', 0x5954d0, True)
            # Candidate virtual calls are reported, never assumed to be controller calls.
            for start, data in self.execs:
                for m in re.finditer(rb'\xff[\x90-\x97]\x30\x01\x00\x00', data):
                    rva = start+m.start()
                    ins = next(self.md.disasm(m[0], rva, count=1), None)
                    if ins:
                        a,z=self.function(rva)
                        if any(a == int(row['function'][0],16) for row in self.result['global_xrefs']):
                            self.result['slot38_candidates'].append(self.instruction(ins))
        self.result['capture_bytes'] = self.used
        return self.result

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--image', action='append', nargs=3, metavar=('LABEL','PATH','SHA256'), required=True)
    parser.add_argument('--output', default='domain-report.json')
    args=parser.parse_args()
    result={'scope':'static PE evidence only; no asserted mapping equivalence', 'images':{}}
    for label,path,pin in args.image:
        inspector=Inspector(path,pin)
        result['images'][label]=inspector.inspect(label)
        print('DOMAIN_IMAGE',label,len(inspector.result['target_xrefs']),len(inspector.result['global_xrefs']),len(inspector.result['functions']),flush=True)
    blob=json.dumps(result,separators=(',',':')).encode()
    Path(args.output).write_bytes(blob)
    packed=base64.b64encode(zlib.compress(blob,9)).decode()
    print('DOMAIN_REPORT_SHA256',hashlib.sha256(blob).hexdigest(),flush=True)
    for n in range(0,len(packed),48000):print('DOMAIN_REPORT_CHUNK',n//48000,packed[n:n+48000],flush=True)

if __name__ == '__main__': main()
