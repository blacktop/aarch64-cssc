"""IDA (disassembler) + Hex-Rays (decompiler) plugin for FEAT_CSSC UMAX/UMIN."""

from __future__ import annotations

import idaapi
import ida_bytes
import ida_hexrays
import ida_ua
import ida_kernwin
import ida_typeinf

LOG_PREFIX = "[CSSC] "
CSSC_PREFIX = 0x43
CSSC_OP_UMAX = 1
CSSC_OP_UMIN = 2
MNEMONIC_INDENT = 8

_g_plugin: "AArch64CSSCPlugin | None" = None


def _ensure_intrinsic_prototypes() -> None:
    til = idaapi.cvar.idati
    for decl in (
        "unsigned __int64 __cssc_umax(unsigned __int64, unsigned __int64);",
        "unsigned __int64 __cssc_umin(unsigned __int64, unsigned __int64);",
    ):
        name = decl.split("(")[0].split()[-1]
        if idaapi.get_named_type(til, name, idaapi.NTF_TYPE) is not None:
            continue
        flags = ida_typeinf.PT_SILENT | ida_typeinf.PT_TYP | ida_typeinf.PT_DEMANDFIELD
        if ida_typeinf.parse_decl(til, decl, flags) <= 0:
            idaapi.msg("%sFailed to register prototype: %s\n" % (LOG_PREFIX, decl))
        else:
            idaapi.msg("%sRegistered prototype for %s\n" % (LOG_PREFIX, name))


class CSSCInstructionVariant:
    def __init__(self, pattern: int, mask: int) -> None:
        self.pattern = pattern
        self.mask = mask

    def matches(self, word: int) -> bool:
        return (word & self.mask) == self.pattern


class CSSCInstruction:
    def __init__(self, op_id: int, name: str, variants: list[CSSCInstructionVariant]) -> None:
        self.op_id = op_id
        self.name = name
        self.variants = variants

    def decode(self, word: int) -> tuple[CSSCInstructionVariant, dict] | None:
        for variant in self.variants:
            if variant.matches(word):
                rd = word & 0x1F
                rn = (word >> 5) & 0x1F
                rm = (word >> 16) & 0x1F
                return variant, {"rd": rd, "rn": rn, "rm": rm}
        return None


CSSC_INSTRUCTIONS = [
    CSSCInstruction(
        CSSC_OP_UMAX,
        "umax",
        [CSSCInstructionVariant(pattern=0x9AC06400, mask=0xFFE0FC00)],
    ),
    CSSCInstruction(
        CSSC_OP_UMIN,
        "umin",
        [CSSCInstructionVariant(pattern=0x9AC06C00, mask=0xFFE0FC00)],
    ),
]
CSSC_MAP = {inst.op_id: inst for inst in CSSC_INSTRUCTIONS}
CSSC_INTRINSICS = {
    CSSC_OP_UMAX: "__cssc_umax",
    CSSC_OP_UMIN: "__cssc_umin",
}

_decode_log_count = 0
_filter_log_count = 0


def _reg_id(reg: int) -> int:
    return reg + 129


class AArch64CSSCHook(idaapi.IDP_Hooks):
    CUSTOM_TYPES = {idaapi.ARM_hlt}

    def ev_ana_insn(self, insn: ida_ua.insn_t) -> int:
        global _decode_log_count

        word = ida_bytes.get_dword(insn.ea)
        for inst in CSSC_INSTRUCTIONS:
            decoded = inst.decode(word)
            if decoded is None:
                continue
            _, operands = decoded
            dtype = idaapi.dt_qword

            if _decode_log_count < 10:
                idaapi.msg(
                    "%s%s decode at 0x%X: rd=x%d, rn=x%d, rm=x%d\n"
                    % (LOG_PREFIX, inst.name.upper(), insn.ea, operands["rd"], operands["rn"], operands["rm"])
                )
                _decode_log_count += 1

            insn.itype = idaapi.ARM_hlt
            insn.size = 4
            insn.segpref = CSSC_PREFIX
            insn.insnpref = inst.op_id

            op0 = insn.ops[0]
            op0.type = idaapi.o_reg
            op0.reg = _reg_id(operands["rd"])
            op0.dtype = dtype

            op1 = insn.ops[1]
            op1.type = idaapi.o_reg
            op1.reg = _reg_id(operands["rn"])
            op1.dtype = dtype

            op2 = insn.ops[2]
            op2.type = idaapi.o_reg
            op2.reg = _reg_id(operands["rm"])
            op2.dtype = dtype
            return insn.size
        return 0

    def ev_emu_insn(self, insn: ida_ua.insn_t) -> bool:
        if insn.itype != idaapi.ARM_hlt or insn.segpref != CSSC_PREFIX:
            return False
        return True

    def ev_out_mnem(self, ctx: idaapi.outctx_t) -> int:
        if ctx.insn.itype not in self.CUSTOM_TYPES or ctx.insn.segpref != CSSC_PREFIX:
            return 0
        inst = CSSC_MAP.get(ctx.insn.insnpref)
        if inst is None:
            return 0
        ctx.out_custom_mnem(inst.name, MNEMONIC_INDENT)
        return 1


class MicroInstruction(ida_hexrays.minsn_t):
    def __init__(self, opcode: int, ea: int) -> None:
        super().__init__(ea)
        self.opcode = opcode
        self.l.zero()
        self.r.zero()
        self.d.zero()


class CallBuilder:
    def __init__(self, cdg: ida_hexrays.cginsn_t, name: str, return_type: idaapi.tinfo_t) -> None:
        self.emitted = False
        self.cdg = cdg
        self.callinfo = ida_hexrays.mcallinfo_t()
        self.callinfo.callee = idaapi.BADADDR
        self.callinfo.solid_args = 0
        self.callinfo.call_spd = 0
        self.callinfo.stkargs_top = 0
        self.callinfo.cc = idaapi.CM_CC_FASTCALL
        self.callinfo.return_type = return_type
        self.callinfo.flags = idaapi.FCI_SPLOK | idaapi.FCI_FINAL | idaapi.FCI_PROP
        self.callinfo.role = idaapi.ROLE_UNK

        stack_region = cdg.mba.get_stack_region()
        glbhigh_off = stack_region.off + stack_region.size
        self.callinfo.visible_memory.add(ida_hexrays.ivl_t(0x00, 0x100000))
        self.callinfo.visible_memory.add(ida_hexrays.ivl_t(glbhigh_off, 0xFFFFFFFFFFFFFFFF - glbhigh_off))
        self.callinfo.spoiled.mem.add(ida_hexrays.ivl_t(0x00, 0x100000))
        self.callinfo.spoiled.mem.add(ida_hexrays.ivl_t(glbhigh_off, 0xFFFFFFFFFFFFFFFF - glbhigh_off))

        self.callins = MicroInstruction(ida_hexrays.m_call, self.cdg.insn.ea)
        self.callins.l.make_helper(name)
        self.callins.d.t = ida_hexrays.mop_f
        self.callins.d.size = 0
        self.callins.d.f = self.callinfo

        if return_type.is_void():
            self.ins = self.callins
        else:
            self.callins.d.size = return_type.get_size()
            self.ins = MicroInstruction(ida_hexrays.m_mov, self.cdg.insn.ea)
            self.ins.l.t = ida_hexrays.mop_d
            self.ins.l.d = self.callins
            self.ins.l.size = self.callins.d.size
            self.ins.d.t = ida_hexrays.mop_r
            self.ins.d.r = 0x00
            self.ins.d.size = self.callins.d.size

    def add_register_argument(self, tinfo: idaapi.tinfo_t, operand: int) -> None:
        arg = ida_hexrays.mcallarg_t()
        arg.t = idaapi.mop_r
        arg.r = operand
        arg.type = tinfo
        arg.size = tinfo.get_size()
        self.callinfo.args.push_back(arg)
        self.callinfo.solid_args += 1

    def set_return_register(self, reg: int) -> None:
        self.ins.d.r = reg

    def emit(self) -> None:
        if not self.emitted:
            self.cdg.mb.insert_into_block(self.ins, self.cdg.mb.tail)
            self.emitted = True


def _unsigned_type(bits: int) -> idaapi.tinfo_t:
    t = idaapi.tinfo_t()
    t.create_int(bits, idaapi.TYPE_UNSIGNED)
    return t


class CSSCMicrocodeFilter(ida_hexrays.microcode_filter_t):
    def __init__(self) -> None:
        super().__init__()
        ida_hexrays.install_microcode_filter(self, True)
        idaapi.msg("%sMicrocode filter installed\n" % LOG_PREFIX)

    def match(self, cdg: ida_hexrays.cginsn_t) -> bool:
        return (
            cdg.insn.itype == idaapi.ARM_hlt
            and cdg.insn.segpref == CSSC_PREFIX
            and cdg.insn.insnpref in CSSC_INTRINSICS
        )

    def apply(self, cdg: ida_hexrays.cginsn_t) -> int:
        global _filter_log_count

        intrinsic_name = CSSC_INTRINSICS.get(cdg.insn.insnpref)
        if intrinsic_name is None:
            return idaapi.MERR_OK

        if _filter_log_count < 10:
            idaapi.msg("%sHex-Rays lowering at 0x%X -> %s\n" % (LOG_PREFIX, cdg.insn.ea, intrinsic_name))
            _filter_log_count += 1

        dest = cdg.insn.ops[0]
        return_type = _unsigned_type(64)

        builder = CallBuilder(cdg, intrinsic_name, return_type)
        builder.set_return_register(dest.reg)

        arg_type = _unsigned_type(64)
        builder.add_register_argument(arg_type, cdg.load_operand(1))
        builder.add_register_argument(arg_type, cdg.load_operand(2))
        builder.emit()
        return idaapi.MERR_OK


class CSSCHexraysHook(ida_hexrays.Hexrays_Hooks):
    def __init__(self, plugin: "AArch64CSSCPlugin") -> None:
        super().__init__()
        self.plugin = plugin

    def hexrays_ready(self) -> int:
        idaapi.msg("%sHex-Rays ready, installing intrinsic lowering\n" % LOG_PREFIX)
        self.plugin.install_microcode_filter()
        if self.plugin.hexrays_hook is not None:
            self.plugin.hexrays_hook.unhook()
            self.plugin.hexrays_hook = None
        return 0

    def hexrays_unloading(self) -> int:
        idaapi.msg("%sHex-Rays unloading, removing intrinsic lowering\n" % LOG_PREFIX)
        self.plugin.remove_microcode_filter()
        return 0


class AArch64CSSCPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC
    comment = "AArch64 FEAT_CSSC support"
    help = "Disassemble FEAT_CSSC instructions"
    wanted_name = "AArch64 CSSC"
    wanted_hotkey = ""

    def __init__(self) -> None:
        super().__init__()
        self.hook: AArch64CSSCHook | None = None
        self.filter: CSSCMicrocodeFilter | None = None
        self.hexrays_hook: CSSCHexraysHook | None = None

    def _is_hexrays_ready(self) -> bool:
        if hasattr(ida_hexrays, "is_loaded"):
            try:
                return ida_hexrays.is_loaded()
            except Exception:
                return False
        if hasattr(ida_hexrays, "hexrays_available"):
            try:
                return ida_hexrays.hexrays_available()
            except Exception:
                return False
        return False

    def install_microcode_filter(self) -> None:
        if self.filter is None:
            _ensure_intrinsic_prototypes()
            self.filter = CSSCMicrocodeFilter()

    def remove_microcode_filter(self) -> None:
        if self.filter is not None:
            ida_hexrays.remove_microcode_filter(self.filter)
            self.filter = None
            idaapi.msg("%sMicrocode filter removed\n" % LOG_PREFIX)

    def _install(self) -> None:
        processor_id = idaapi.ph_get_id()
        if processor_id != idaapi.PLFM_ARM:
            idaapi.msg("%sSkipping: processor id %d is not ARM\n" % (LOG_PREFIX, processor_id))
            return

        idaapi.msg("%sInstalling FEAT_CSSC hooks\n" % LOG_PREFIX)
        self.hook = AArch64CSSCHook()
        self.hook.hook()

        if self._is_hexrays_ready():
            idaapi.msg("%sHex-Rays already initialized, installing intrinsic lowering now\n" % LOG_PREFIX)
            self.install_microcode_filter()
        else:
            idaapi.msg("%sHex-Rays not initialized yet; deferring intrinsic lowering\n" % LOG_PREFIX)
            if self.hexrays_hook is None:
                self.hexrays_hook = CSSCHexraysHook(self)
                self.hexrays_hook.hook()

    def init(self) -> int:
        idaapi.msg("%s%s init requested\n" % (LOG_PREFIX, self.wanted_name))
        ida_kernwin.execute_sync(self._install, ida_kernwin.MFF_WRITE)
        return idaapi.PLUGIN_KEEP

    def run(self, _arg) -> None:
        idaapi.msg("%sRun invoked\n" % LOG_PREFIX)
        if self._is_hexrays_ready():
            idaapi.msg("%sHex-Rays initialized via run, installing intrinsic lowering now\n" % LOG_PREFIX)
            self.install_microcode_filter()
        else:
            idaapi.msg("%sHex-Rays still not initialized; deferring intrinsic lowering\n" % LOG_PREFIX)
            if self.hexrays_hook is None:
                self.hexrays_hook = CSSCHexraysHook(self)
                self.hexrays_hook.hook()

    def term(self) -> None:
        if self.hook is not None:
            self.hook.unhook()
            self.hook = None
        if self.hexrays_hook is not None:
            self.hexrays_hook.unhook()
            self.hexrays_hook = None
        self.remove_microcode_filter()
        idaapi.msg("%s%s unloaded\n" % (LOG_PREFIX, self.wanted_name))


def PLUGIN_ENTRY() -> AArch64CSSCPlugin:
    global _g_plugin
    _g_plugin = AArch64CSSCPlugin()
    return _g_plugin
