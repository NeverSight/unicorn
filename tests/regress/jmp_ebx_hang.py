""" See https://github.com/unicorn-engine/unicorn/issues/82 """

import regress
from unicorn import *
from unicorn.x86_const import *

CODE_ADDR = 0x10101000
CODE = b'\xff\xe3'  # jmp ebx


class JumEbxHang(regress.RegressTest):
    def runTest(self):
        mu = Uc(UC_ARCH_X86, UC_MODE_32)

        mu.mem_map(CODE_ADDR, 1024 * 4)
        mu.mem_write(CODE_ADDR, CODE)
        # Exercise the target fetch. A one-instruction budget may stop after
        # the jump without attempting that fetch on some host translators.
        # The timeout still bounds a recurrence of the original hang.
        mu.reg_write(UC_X86_REG_EBX, 0x0)

        regress.logger.debug(">>> jmp ebx (ebx = 0)")
        with self.assertRaises(UcError) as m:
            mu.emu_start(CODE_ADDR, CODE_ADDR + len(CODE), timeout=UC_SECOND_SCALE)

        self.assertEqual(m.exception.errno, UC_ERR_FETCH_UNMAPPED)

        regress.logger.debug(">>> jmp ebx (ebx = 0xaa96a47f)")
        mu = Uc(UC_ARCH_X86, UC_MODE_32)
        mu.mem_map(CODE_ADDR, 1024 * 4)
        # If we write this address to EBX then the emulator hangs on emu_start
        mu.reg_write(UC_X86_REG_EBX, 0xaa96a47f)
        mu.mem_write(CODE_ADDR, CODE)

        with self.assertRaises(UcError) as m:
            mu.emu_start(CODE_ADDR, CODE_ADDR + len(CODE), timeout=UC_SECOND_SCALE)

        self.assertEqual(m.exception.errno, UC_ERR_FETCH_UNMAPPED)


if __name__ == '__main__':
    regress.main()
