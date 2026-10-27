"""Bounded CTZ translation plans; no executable emitter or automatic selection.

A replacement branch plus RBIT/CLZ/branch needs a signed executable arena and
exception-PC qualification. Returning an encoding plan never grants those.
"""
from zeta_x1_compat import cssc


def branch(source, target):
    if not all(type(x) is int and 0 <= x < 1 << 64 and not x & 3 for x in (source,target)):
        raise ValueError('branch PCs must be aligned uint64 addresses')
    displacement = target-source
    if not -(1<<27) <= displacement < (1<<27):
        raise ValueError('branch target outside signed imm26 range')
    return 0x14000000 | ((displacement//4) & 0x03ffffff)


def plan_ctz(word, original_pc, arena_pc):
    if type(word) is not int or not 0 <= word < 1 << 32:
        raise ValueError('instruction must be uint32')
    if cssc(word) != 'ctz':
        raise ValueError('only exact W/X CTZ forms are supported')
    # Validate every address, including the final fallthrough, without wrap.
    if not 0 <= original_pc <= (1<<64)-8 or not 0 <= arena_pc <= (1<<64)-12:
        raise ValueError('PC range overflows')
    if arena_pc < original_pc+8 and original_pc < arena_pc+12:
        raise ValueError('thunk overlaps original instruction or fallthrough')
    outward = branch(original_pc,arena_pc)
    backward = branch(arena_pc+8,original_pc+4)
    sf=word&0x80000000;rd=word&31;rn=(word>>5)&31
    words=[sf|0x5ac00000|(rn<<5)|rd, sf|0x5ac01000|(rd<<5)|rd, backward]
    return {'schema':'zeta-x1-ctz-thunk-plan-v1','original_pc':original_pc,'original_word':word,
        'replacement_word':outward,'arena_pc':arena_pc,'arena_words':words,
        'destination':rd,'source':rn,'bits':64 if sf else 32,'resume_pc':original_pc+4,
        'scratch_registers':[],'nzcv_modified':False,'sp_modified':False,
        'pc_stages':[
            {'pc':arena_pc,'completed_steps':0,'pending_operation':'original-ctz'},
            {'pc':arena_pc+4,'completed_steps':1,'pending_operation':'clz-destination'},
            {'pc':arena_pc+8,'completed_steps':2,'pending_operation':'resume-only'}],
        'selected_for_conversion':False,
        'required_before_selection':['Arena placement/ownership, signature and trust binding',
            'No existing live code/data overwritten; reachable branch targets verified',
            'Async signal delivery must complete pure pending operation and expose original fallthrough state',
            'Debugger, fault, exception-PC, unwind and cache/tool-manifest qualification'],
        'limits':['A raw PC alias alone cannot hide the intermediate reversed destination',
            'No kernel async signal completion or debugger integration is implemented by this planner']}
