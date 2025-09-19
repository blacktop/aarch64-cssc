"""IDA (disassembler) + Hex-Rays (decompiler) plugin for FEAT_CSSC UMAX/UMIN."""

from __future__ import annotations

import idaapi
import ida_bytes
import ida_hexrays
import ida_ua
import ida_kernwin
import ida_typeinf
import ida_xref

LOG_PREFIX = "[CSSC] "
CSSC_PREFIX = 0x43
CSSC_OP_UMAX = 1
CSSC_OP_UMIN = 2
MNEMONIC_INDENT = 16

_g_plugin: "AArch64CSSCPlugin | None" = None


def _ensure_intrinsic_prototypes() -> None:
    til = ida_typeinf.get_idati()  # Correct way to get type library in IDA 9.2
    for decl in (
        "unsigned __int64 __cssc_umax(unsigned __int64, unsigned __int64);",
        "unsigned __int64 __cssc_umin(unsigned __int64, unsigned __int64);",
        "unsigned int __cssc_umax32(unsigned int, unsigned int);",
        "unsigned int __cssc_umin32(unsigned int, unsigned int);",
    ):
        name = decl.split("(")[0].split()[-1]
        # Check if type already exists
        if ida_typeinf.get_named_type(til, name, ida_typeinf.NTF_TYPE) is not None:
            continue

        try:
            # Try to import the type declaration
            # PT_SIL means silent mode (suppress error messages)
            result = ida_typeinf.idc_parse_types(decl, ida_typeinf.PT_SIL)
            if result == 0:
                # Fallback: try simpler approach
                tinfo = ida_typeinf.tinfo_t()
                if ida_typeinf.parse_decl(tinfo, til, decl, 0) is not None:
                    idaapi.msg("%sRegistered prototype for %s\n" % (LOG_PREFIX, name))
                else:
                    idaapi.msg("%sFailed to register prototype: %s\n" % (LOG_PREFIX, decl))
            else:
                idaapi.msg("%sRegistered prototype for %s\n" % (LOG_PREFIX, name))
        except Exception as e:
            idaapi.msg("%sError registering %s: %s\n" % (LOG_PREFIX, name, str(e)))


class CSSCInstructionVariant:
    def __init__(self, pattern: int, mask: int, dtype: int, reg_prefix: str) -> None:
        self.pattern = pattern
        self.mask = mask
        self.dtype = dtype
        self.reg_prefix = reg_prefix  # 'x' for 64-bit, 'w' for 32-bit

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
                return variant, {"rd": rd, "rn": rn, "rm": rm, "dtype": variant.dtype, "reg_prefix": variant.reg_prefix}
        return None


CSSC_INSTRUCTIONS = [
    CSSCInstruction(
        CSSC_OP_UMAX,
        "UMAX",
        [
            CSSCInstructionVariant(
                pattern=0x9AC06400, mask=0xFFE0FC00, dtype=idaapi.dt_qword, reg_prefix="x"
            ),  # 64-bit
            CSSCInstructionVariant(
                pattern=0x1AC06400, mask=0xFFE0FC00, dtype=idaapi.dt_dword, reg_prefix="w"
            ),  # 32-bit
        ],
    ),
    CSSCInstruction(
        CSSC_OP_UMIN,
        "UMIN",
        [
            CSSCInstructionVariant(
                pattern=0x9AC06C00, mask=0xFFE0FC00, dtype=idaapi.dt_qword, reg_prefix="x"
            ),  # 64-bit
            CSSCInstructionVariant(
                pattern=0x1AC06C00, mask=0xFFE0FC00, dtype=idaapi.dt_dword, reg_prefix="w"
            ),  # 32-bit
        ],
    ),
]
CSSC_MAP = {inst.op_id: inst for inst in CSSC_INSTRUCTIONS}
CSSC_INTRINSICS = {
    CSSC_OP_UMAX: "__cssc_umax",
    CSSC_OP_UMIN: "__cssc_umin",
}

_decode_log_count = 0
_filter_log_count = 0


def _reg_id(reg: int, is_64bit: bool = True) -> int:
    # IDA register IDs: 129+ for X registers, 1+ for W registers
    # Validate register number (0-31, where 31 is ZR/WZR)
    if reg < 0 or reg > 31:
        idaapi.msg("%sWarning: Invalid register number %d\n" % (LOG_PREFIX, reg))
        reg = min(max(reg, 0), 31)  # Clamp to valid range

    if is_64bit:
        return reg + 129  # X0-X30, XZR
    else:
        return reg + 1  # W0-W30, WZR


class AArch64CSSCHook(idaapi.IDP_Hooks):
    CUSTOM_TYPES = {idaapi.ARM_hlt}

    def ev_ana_insn(self, insn: ida_ua.insn_t) -> int:
        global _decode_log_count

        word = ida_bytes.get_dword(insn.ea)
        for inst in CSSC_INSTRUCTIONS:
            decoded = inst.decode(word)
            if decoded is None:
                continue
            variant, operands = decoded
            dtype = operands["dtype"]
            reg_prefix = operands["reg_prefix"]

            if _decode_log_count < 10:
                idaapi.msg(
                    "%s%s decode at 0x%X: rd=%s%d, rn=%s%d, rm=%s%d\n"
                    % (
                        LOG_PREFIX,
                        inst.name.upper(),
                        insn.ea,
                        reg_prefix,
                        operands["rd"],
                        reg_prefix,
                        operands["rn"],
                        reg_prefix,
                        operands["rm"],
                    )
                )
                _decode_log_count += 1

            insn.itype = idaapi.ARM_hlt
            insn.size = 4
            insn.segpref = CSSC_PREFIX
            insn.insnpref = inst.op_id

            is_64bit = dtype == idaapi.dt_qword

            op0 = insn.ops[0]
            op0.type = idaapi.o_reg
            op0.reg = _reg_id(operands["rd"], is_64bit)
            op0.dtype = dtype

            op1 = insn.ops[1]
            op1.type = idaapi.o_reg
            op1.reg = _reg_id(operands["rn"], is_64bit)
            op1.dtype = dtype

            op2 = insn.ops[2]
            op2.type = idaapi.o_reg
            op2.reg = _reg_id(operands["rm"], is_64bit)
            op2.dtype = dtype
            return insn.size
        return 0

    def ev_emu_insn(self, insn: ida_ua.insn_t) -> bool:
        if insn.itype != idaapi.ARM_hlt or insn.segpref != CSSC_PREFIX:
            return False

        # UMAX/UMIN instructions don't change control flow
        # They are like regular data processing instructions
        # Add a flow cross-reference to the next instruction
        ida_ua.add_cref(insn.ea, insn.ea + insn.size, ida_xref.fl_F)

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
    def __init__(self, cdg: ida_hexrays.cginsn_t, name: str, return_type: ida_typeinf.tinfo_t) -> None:
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
            # Get size and ensure it's valid
            size = return_type.get_size()
            if size <= 0 or size > 8:
                # Default to 8 bytes for 64-bit or 4 bytes for 32-bit based on type
                size = 8 if return_type.is_uint64() or return_type.is_int64() else 4

            self.callins.d.size = size
            self.ins = MicroInstruction(ida_hexrays.m_mov, self.cdg.insn.ea)
            self.ins.l.t = ida_hexrays.mop_d
            self.ins.l.d = self.callins
            self.ins.l.size = size
            self.ins.d.t = ida_hexrays.mop_r
            self.ins.d.r = 0x00
            self.ins.d.size = size

    def add_register_argument(self, tinfo: ida_typeinf.tinfo_t, operand: int) -> None:
        arg = ida_hexrays.mcallarg_t()
        arg.t = idaapi.mop_r
        arg.r = operand
        arg.type = tinfo
        # Ensure size is valid
        size = tinfo.get_size()
        if size <= 0 or size > 8:
            size = 8 if tinfo.is_uint64() or tinfo.is_int64() else 4
        arg.size = size
        self.callinfo.args.push_back(arg)
        self.callinfo.solid_args += 1

    def set_return_register(self, reg: int) -> None:
        self.ins.d.r = reg

    def emit(self) -> None:
        if not self.emitted:
            self.cdg.mb.insert_into_block(self.ins, self.cdg.mb.tail)
            self.emitted = True


def _unsigned_type(bits: int) -> ida_typeinf.tinfo_t:
    # Create proper unsigned integer types for IDA 9.2
    t = ida_typeinf.tinfo_t()

    if bits == 32:
        # Create 32-bit unsigned int using the simple type method
        t.create_simple_type(ida_typeinf.BTF_UINT32)
    elif bits == 64:
        # Create 64-bit unsigned int using the simple type method
        t.create_simple_type(ida_typeinf.BTF_UINT64)
    else:
        # Default to 32-bit unsigned int
        t.create_simple_type(ida_typeinf.BTF_UINT32)

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
        # Check operand size to determine if it's 32-bit or 64-bit
        is_32bit = cdg.insn.ops[0].dtype == idaapi.dt_dword

        if is_32bit:
            # Use 32-bit intrinsics
            intrinsic_name = intrinsic_name + "32"
            return_type = _unsigned_type(32)
            arg_type = _unsigned_type(32)
        else:
            # Use 64-bit intrinsics
            return_type = _unsigned_type(64)
            arg_type = _unsigned_type(64)

        builder = CallBuilder(cdg, intrinsic_name, return_type)
        builder.set_return_register(dest.reg)

        builder.add_register_argument(arg_type, cdg.load_operand(1))
        builder.add_register_argument(arg_type, cdg.load_operand(2))
        builder.emit()
        return idaapi.MERR_OK


# CSSCHexraysHook removed - initialization happens on first use


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

    def try_install_filter(self) -> bool:
        """Try to install the microcode filter."""
        if self.filter is not None:
            return True

        try:
            if not ida_hexrays.init_hexrays_plugin():
                return False

            idaapi.msg("%sHex-Rays available, installing intrinsic lowering\n" % LOG_PREFIX)
            _ensure_intrinsic_prototypes()
            self.filter = CSSCMicrocodeFilter()
            return True
        except Exception as e:
            idaapi.msg("%sError in try_install_filter: %s\n" % (LOG_PREFIX, str(e)))
            return False

    def init(self) -> int:
        idaapi.msg("%s%s init requested\n" % (LOG_PREFIX, self.wanted_name))

        # Check processor type
        processor_id = idaapi.ph_get_id()
        if processor_id != idaapi.PLFM_ARM:
            idaapi.msg("%sSkipping: processor id %d is not ARM\n" % (LOG_PREFIX, processor_id))
            return idaapi.PLUGIN_SKIP

        # Install hooks for disassembly
        idaapi.msg("%sInstalling FEAT_CSSC hooks\n" % LOG_PREFIX)
        self.hook = AArch64CSSCHook()
        self.hook.hook()

        # Try to initialize Hex-Rays but don't fail if not available
        if not self.try_install_filter():
            idaapi.msg("%sHex-Rays not available yet, deferring intrinsic lowering\n" % LOG_PREFIX)

        # Always keep the plugin loaded for disassembly
        return idaapi.PLUGIN_KEEP

    def run(self, _arg) -> None:
        idaapi.msg("%sRun invoked\n" % LOG_PREFIX)
        # Try to initialize if filter not yet installed
        if self.filter is None:
            if self.try_install_filter():
                idaapi.msg("%sFilter successfully installed\n" % LOG_PREFIX)
            else:
                idaapi.msg("%sHex-Rays still not available\n" % LOG_PREFIX)

    def term(self) -> None:
        if self.hook is not None:
            self.hook.unhook()
            self.hook = None
        if self.filter is not None:
            try:
                ida_hexrays.remove_microcode_filter(self.filter)
            except (AttributeError, RuntimeError) as e:
                # Filter might already be removed or Hex-Rays not available
                idaapi.msg("%sNote: Could not remove filter: %s\n" % (LOG_PREFIX, str(e)))
            self.filter = None
        idaapi.msg("%s%s unloaded\n" % (LOG_PREFIX, self.wanted_name))


def PLUGIN_ENTRY() -> AArch64CSSCPlugin:
    global _g_plugin
    _g_plugin = AArch64CSSCPlugin()
    return _g_plugin
