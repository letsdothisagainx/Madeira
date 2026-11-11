#!/usr/bin/env python3
"""Bounded AMD64 HTMLIPC sender instruction witnesses from original PE bytes.

Uses the inspection module's PE/RTTI reader. No PE instructions are executed.
A witness connects a stack wrapper RTTI identity, a constant command argument,
and a call forwarding that exact object/command to the ordinary encoder.
Absent commands and indirect control-flow exits remain unresolved.
"""
import re


def extract_sender_evidence(raw, wire_class):
    import capstone as cs
    a = wire_class(raw)
    if a.bits != 64:
        return {'scope': 'AMD64 sender witnesses only', 'bindings': {}, 'count': 0}
    proofs = {}

    def addr(op, state):
        mem = op.mem
        if mem.index:
            return None
        family = a.reg(mem.base)
        base = state.get(family)
        if family in ('rsp', 'rbp'):
            return ('stack', family, mem.disp)
        if base and base[0] in ('stack', 'arg'):
            return (*base[:-1], base[-1] + mem.disp)
        return None

    def move(item, state):
        out = dict(state)
        ops = item.operands
        value = None
        if len(ops) == 2 and ops[0].type == cs.x86.X86_OP_REG:
            if item.mnemonic == 'mov':
                if ops[1].type == cs.x86.X86_OP_IMM:
                    value = ('constant', ops[1].imm)
                elif ops[1].type == cs.x86.X86_OP_REG:
                    value = state.get(a.reg(ops[1].reg))
                    if value and value[0] in ('stack', 'arg', 'vtable') and ops[0].size != 8:
                        value = None
            elif item.mnemonic == 'lea' and ops[0].size == 8 and ops[1].type == cs.x86.X86_OP_MEM:
                if ops[1].mem.base == cs.x86.X86_REG_RIP:
                    target = item.address + item.size + ops[1].mem.disp
                    if target in a.vtables:
                        value = ('vtable', target)
                else:
                    value = addr(ops[1], state)
        for reg in item.regs_access()[1]:
            out.pop(a.reg(reg), None)
        if value is not None:
            out[a.reg(ops[0].reg)] = value
        return out

    def encoder(target):
        """Identify the ordinary serializer's actual size/command contracts."""
        try:
            ins = list(a.md.disasm(a.data(target, 320), target))
        except ValueError:
            return False
        constants = [o.imm for i in ins if i.mnemonic == 'cmp' for o in i.operands if o.type == cs.x86.X86_OP_IMM]
        virtual_size = any(i.mnemonic == 'call' and len(i.operands) == 1 and
                           i.operands[0].type == cs.x86.X86_OP_MEM and i.operands[0].mem.disp == 0x40 for i in ins)
        return 0x8000000 in constants and 0x9e in constants and virtual_size

    def forwarding(target, kind):
        key = (target, kind)
        if key in proofs:
            return proofs[key]
        state = {'rdx': ('command', 0), 'r8': ('arg', 0)} if kind == 'controller' else {'rcx': ('command', 0), 'rdx': ('arg', 0)}
        try:
            ins = list(a.md.disasm(a.data(target, 640), target))
        except ValueError:
            proofs[key] = None
            return None
        for item in ins:
            ops = item.operands
            if item.mnemonic in ('ret', 'int3', 'ud2'):
                break
            if item.mnemonic == 'call':
                if ops and ops[0].type == cs.x86.X86_OP_IMM and state.get('r8') == ('command', 0) and state.get('rcx') in (('arg', 0), ('arg', 8)) and encoder(ops[0].imm):
                    proofs[key] = {'forwarder_rva': hex(target), 'encoder_rva': hex(ops[0].imm),
                                   'call': a.row(item), 'object_offset': state['rcx'][1],
                                   'argument_order': kind}
                    return proofs[key]
                for reg in ('rax', 'rcx', 'rdx', 'r8', 'r9', 'r10', 'r11'):
                    state.pop(reg, None)
            else:
                state = move(item, state)
        proofs[key] = None
        return None

    bindings = {}
    unresolved = 0
    for section, code in a.code:
        for match in re.finditer(rb'[\x40-\x4f]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]....', code, re.S):
            start = section + match.start()
            first = next(a.md.disasm(match[0], start, count=1), None)
            if not first or first.size != 7 or len(first.operands) != 2 or first.operands[1].mem.base != cs.x86.X86_REG_RIP:
                continue
            vt = start + 7 + first.operands[1].mem.disp
            if vt not in a.vtables:
                continue
            # Each path carries its own register and stack-wrapper identities.
            pending = [(start, {}, {})]
            visited = set()
            steps = 0
            while pending:
                pc, regs, objects = pending.pop()
                key = (pc, tuple(sorted(regs.items())), tuple(sorted(objects.items())))
                if key in visited:
                    continue
                visited.add(key)
                steps += 1
                if steps > 4096 or not start <= pc < start + 4096:
                    unresolved += 1
                    continue
                try:
                    item = next(a.md.disasm(a.data(pc, 15), pc, count=1), None)
                except ValueError:
                    item = None
                if not item:
                    continue
                ops = item.operands
                next_objects = dict(objects)
                if item.mnemonic == 'mov' and len(ops) == 2 and ops[0].type == cs.x86.X86_OP_MEM:
                    location = addr(ops[0], regs)
                    if location and location[0] == 'stack':
                        if ops[1].type == cs.x86.X86_OP_REG:
                            value = regs.get(a.reg(ops[1].reg))
                            if value and value[0] == 'vtable' and ops[0].size == 8:
                                next_objects[location] = (value[1], item.address)
                            else:
                                next_objects.pop(location, None)
                        else:
                            next_objects.pop(location, None)
                next_regs = move(item, regs)
                if item.mnemonic == 'call':
                    if ops and ops[0].type == cs.x86.X86_OP_IMM:
                        for kind, command_reg, object_reg, adjustment in [('controller', 'rdx', 'r8', -8), ('js', 'rcx', 'rdx', 0)]:
                            command, object_ = regs.get(command_reg), regs.get(object_reg)
                            if not command or command[0] != 'constant' or not 1 <= command[1] <= 511 or not object_ or object_[0] != 'stack':
                                continue
                            location = (*object_[:-1], object_[-1] + adjustment)
                            wrapper = objects.get(location)
                            if not wrapper:
                                continue
                            proof = forwarding(ops[0].imm, kind)
                            if not proof:
                                continue
                            name = a.vtables[wrapper[0]]
                            number = str(command[1])
                            witness = {'name': name, 'wrapper_vtable_rva': hex(wrapper[0]),
                                       'wrapper_store_rva': hex(wrapper[1]), 'call': a.row(item),
                                       'object_argument': {'base': object_[1], 'offset': object_[2]},
                                       'forwarding': proof}
                            if number in bindings and bindings[number]['name'] != name:
                                raise ValueError('conflicting sender command/type instruction witnesses')
                            bindings[number] = witness
                    for reg in ('rax', 'rcx', 'rdx', 'r8', 'r9', 'r10', 'r11'):
                        next_regs.pop(reg, None)
                if item.mnemonic in ('ret', 'int3', 'ud2'):
                    continue
                if item.group(cs.CS_GRP_JUMP):
                    if not ops or ops[0].type != cs.x86.X86_OP_IMM:
                        unresolved += 1
                        continue
                    pending.append((ops[0].imm, dict(next_regs), dict(next_objects)))
                    if item.mnemonic == 'jmp':
                        continue
                pending.append((item.address + item.size, next_regs, next_objects))
    return {'scope': 'Bounded AMD64 stack-wrapper, constant-command and ordinary encoder forwarding instruction witnesses; not exhaustive semantic equivalence.',
            'bindings': bindings, 'count': len(bindings), 'bounded_or_indirect_exits': unresolved,
            'forwarders': [p for p in proofs.values() if p]}
