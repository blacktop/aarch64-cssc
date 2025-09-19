"""IDA (disassembler) + Hex-Rays (decompiler) plugin for FEAT_CSSC UMAX/UMIN."""

from __future__ import annotations

import idaapi
import ida_bytes
import ida_ua
import ida_kernwin
import ida_typeinf
import ida_xref
import ida_idp

LOG_PREFIX = "[CSSC] "
CSSC_PREFIX = 0x43
CSSC_OP_UMAX = 1
CSSC_OP_UMIN = 2
MNEMONIC_INDENT = 16

_g_plugin: "AArch64CSSCPlugin | None" = None

# Custom instruction type for CSSC instructions
try:
    from ida_idp import CUSTOM_INSN_ITYPE

    ARM_CSSC = CUSTOM_INSN_ITYPE
except ImportError:
    ARM_CSSC = 0x8000


def _ensure_intrinsic_prototypes() -> None:
    """Register CSSC intrinsic prototypes if not already present."""
    til = ida_typeinf.get_idati()
    for decl in (
        "unsigned __int64 __cssc_umax(unsigned __int64, unsigned __int64);",
        "unsigned __int64 __cssc_umin(unsigned __int64, unsigned __int64);",
        "unsigned int __cssc_umax32(unsigned int, unsigned int);",
        "unsigned int __cssc_umin32(unsigned int, unsigned int);",
    ):
        name = decl.split("(")[0].split()[-1]
        # Check if type already exists
        result = ida_typeinf.get_named_type(til, name, ida_typeinf.NTF_TYPE)
        if result is not None:
            continue

        # In IDA 9.2, just use parse_decl - it both parses and registers the type
        tinfo = ida_typeinf.tinfo_t()
        parsed_name = ida_typeinf.parse_decl(tinfo, til, decl, 0)
        if parsed_name is not None:
            idaapi.msg("%sRegistered prototype for %s\n" % (LOG_PREFIX, name))
        else:
            idaapi.msg("%sFailed to parse prototype: %s\n" % (LOG_PREFIX, decl))


class CSSCInstructionVariant:
    def __init__(self, pattern: int, mask: int, dtype: int, reg_prefix: str) -> None:
        self.pattern = pattern
        self.mask = mask
        self.dtype = dtype
        self.reg_prefix = reg_prefix

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


def _reg_id(reg: int, is_64bit: bool = True) -> int:
    """Map register number to IDA register ID.

    For AArch64 in IDA:
    - X0-X30 are IDs 129-159
    - XZR is ID 160 (reg 31)
    - W0-W30 are IDs 1-31
    - WZR is ID 32 (reg 31)
    """
    if reg < 0 or reg > 31:
        idaapi.msg("%sWarning: Invalid register number %d\n" % (LOG_PREFIX, reg))
        reg = min(max(reg, 0), 31)

    if is_64bit:
        # X registers: X0=129, X1=130, ..., X30=159, XZR=160
        return 129 + reg
    else:
        # W registers: W0=1, W1=2, ..., W30=31, WZR=32
        return 1 + reg


class AArch64CSSCHook(idaapi.IDP_Hooks):
    # Use custom instruction type to avoid any ARM semantics
    CUSTOM_TYPES = {ARM_CSSC}

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

            # Use custom instruction type
            insn.itype = ARM_CSSC
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
        if insn.itype != ARM_CSSC or insn.segpref != CSSC_PREFIX:
            return False

        # Add normal flow to next instruction (critical for control flow)
        ida_xref.add_cref(insn.ea, insn.ea + insn.size, ida_xref.fl_F)

        return True

    def ev_out_mnem(self, ctx: idaapi.outctx_t) -> int:
        if ctx.insn.itype not in self.CUSTOM_TYPES or ctx.insn.segpref != CSSC_PREFIX:
            return 0
        inst = CSSC_MAP.get(ctx.insn.insnpref)
        if inst is None:
            return 0
        # Output uppercase mnemonic with standard IDA indent
        ctx.out_custom_mnem(inst.name, MNEMONIC_INDENT)
        return 1


# Global variable to store the microcode filter instance
_microcode_filter = None


def _unsigned_type(bits: int):
    """Create unsigned integer type for IDA 9.2."""
    t = ida_typeinf.tinfo_t()
    if bits == 32:
        t.create_simple_type(ida_typeinf.BTF_UINT32)
    elif bits == 64:
        t.create_simple_type(ida_typeinf.BTF_UINT64)
    else:
        t.create_simple_type(ida_typeinf.BTF_UINT32)
    return t


def _install_hexrays_filter():
    """Install the Hex-Rays microcode filter."""
    global _microcode_filter

    if _microcode_filter is not None:
        return True

    try:
        # Only import ida_hexrays when we're actually installing the filter
        import ida_hexrays

        # Ensure prototypes are registered
        _ensure_intrinsic_prototypes()

        # Define helper classes inside this function to avoid module-level ida_hexrays usage
        class MicroInstruction(ida_hexrays.minsn_t):
            def __init__(self, opcode, ea):
                super().__init__(ea)
                self.opcode = opcode
                self.l.zero()
                self.r.zero()
                self.d.zero()

        class CallBuilder:
            def __init__(self, cdg, name, return_type):
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
                    size = return_type.get_size()
                    if size <= 0 or size > 8:
                        size = 8 if return_type.is_uint64() or return_type.is_int64() else 4

                    self.callins.d.size = size
                    self.ins = MicroInstruction(ida_hexrays.m_mov, self.cdg.insn.ea)
                    self.ins.l.t = ida_hexrays.mop_d
                    self.ins.l.d = self.callins
                    self.ins.l.size = size
                    self.ins.d.t = ida_hexrays.mop_r
                    self.ins.d.r = 0x00
                    self.ins.d.size = size

            def add_register_argument(self, tinfo, operand):
                arg = ida_hexrays.mcallarg_t()
                arg.t = idaapi.mop_r
                arg.r = operand
                arg.type = tinfo
                size = tinfo.get_size()
                if size <= 0 or size > 8:
                    size = 8 if tinfo.is_uint64() or tinfo.is_int64() else 4
                arg.size = size
                self.callinfo.args.push_back(arg)
                self.callinfo.solid_args += 1

            def set_return_register(self, reg):
                self.ins.d.r = reg

            def emit(self):
                if not self.emitted:
                    self.cdg.mb.insert_into_block(self.ins, self.cdg.mb.tail)
                    self.emitted = True

        # Create and install the microcode filter
        class CSSCMicrocodeFilter(ida_hexrays.microcode_filter_t):
            def __init__(self):
                super().__init__()
                self.log_count = 0

            def match(self, cdg):
                return (
                    cdg.insn.itype == ARM_CSSC
                    and cdg.insn.segpref == CSSC_PREFIX
                    and cdg.insn.insnpref in CSSC_INTRINSICS
                )

            def apply(self, cdg):
                intrinsic_name = CSSC_INTRINSICS.get(cdg.insn.insnpref)
                if intrinsic_name is None:
                    return idaapi.MERR_OK

                if self.log_count < 10:
                    idaapi.msg("%sApplying intrinsic %s at 0x%X\n" % (LOG_PREFIX, intrinsic_name, cdg.insn.ea))
                    self.log_count += 1

                dest = cdg.insn.ops[0]
                is_32bit = dest.dtype == idaapi.dt_dword

                if is_32bit:
                    intrinsic_name = intrinsic_name + "32"
                    return_type = _unsigned_type(32)
                    arg_type = _unsigned_type(32)
                else:
                    return_type = _unsigned_type(64)
                    arg_type = _unsigned_type(64)

                # Build the intrinsic call
                builder = CallBuilder(cdg, intrinsic_name, return_type)

                # Load the destination operand for the return value
                dst_reg = cdg.load_operand(0)
                builder.set_return_register(dst_reg)

                # Add the two source operands as arguments
                builder.add_register_argument(arg_type, cdg.load_operand(1))
                builder.add_register_argument(arg_type, cdg.load_operand(2))

                # Emit the call instruction
                builder.emit()

                return idaapi.MERR_OK

        _microcode_filter = CSSCMicrocodeFilter()
        if ida_hexrays.install_microcode_filter(_microcode_filter, True):
            idaapi.msg("%sMicrocode filter installed successfully\n" % LOG_PREFIX)
            return True
        else:
            idaapi.msg("%sFailed to install microcode filter\n" % LOG_PREFIX)
            _microcode_filter = None
            return False

    except Exception as e:
        idaapi.msg("%sError installing filter: %s\n" % (LOG_PREFIX, str(e)))
        _microcode_filter = None
        return False


class AArch64CSSCPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC
    comment = "AArch64 FEAT_CSSC support"
    help = "Disassemble FEAT_CSSC instructions"
    wanted_name = "AArch64 CSSC"
    wanted_hotkey = ""

    def __init__(self) -> None:
        super().__init__()
        self.hook: AArch64CSSCHook | None = None

    def init(self) -> int:
        idaapi.msg("%s%s init requested\n" % (LOG_PREFIX, self.wanted_name))

        # Check processor type
        processor_id = idaapi.ph_get_id()
        if processor_id != idaapi.PLFM_ARM:
            idaapi.msg("%sSkipping: processor id %d is not ARM\n" % (LOG_PREFIX, processor_id))
            return idaapi.PLUGIN_SKIP

        # Check if Hex-Rays is available
        if not idaapi.init_hexrays_plugin():
            idaapi.msg("%sHex-Rays not ready, deferring plugin init (will auto-retry)\n" % LOG_PREFIX)
            return idaapi.PLUGIN_SKIP  # IDA will retry loading this plugin later

        # Hex-Rays is ready! Install everything
        idaapi.msg("%sHex-Rays detected, installing FEAT_CSSC support\n" % LOG_PREFIX)

        # Install hooks for disassembly
        self.hook = AArch64CSSCHook()
        self.hook.hook()
        idaapi.msg("%sDisassembly hooks installed\n" % LOG_PREFIX)

        # Install Hex-Rays microcode filter
        if _install_hexrays_filter():
            idaapi.msg("%sDecompiler support enabled\n" % LOG_PREFIX)
        else:
            idaapi.msg("%sWarning: Failed to install decompiler filter\n" % LOG_PREFIX)

        return idaapi.PLUGIN_KEEP

    def run(self, _arg) -> None:
        idaapi.msg("%sPlugin already active\n" % LOG_PREFIX)
        # Everything is already installed in init()
        # This is only called if user manually runs the plugin
        pass

    def term(self) -> None:
        global _microcode_filter

        if self.hook is not None:
            self.hook.unhook()
            self.hook = None

        if _microcode_filter is not None:
            try:
                import ida_hexrays

                ida_hexrays.remove_microcode_filter(_microcode_filter)
            except:
                pass
            _microcode_filter = None

        idaapi.msg("%s%s unloaded\n" % (LOG_PREFIX, self.wanted_name))


def PLUGIN_ENTRY() -> AArch64CSSCPlugin:
    global _g_plugin
    _g_plugin = AArch64CSSCPlugin()
    return _g_plugin
