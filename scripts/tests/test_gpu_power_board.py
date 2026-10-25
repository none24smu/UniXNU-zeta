"""Host tests of package/GpuPowerBoard.h: the gated stages against a simulated register file, built with the host C compiler."""
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

DRIVER = r'''
#include "GpuPowerBoard.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// Five windows of simulated registers. CX powers on (hw-ctrl PWR_ON, GDSCR PWR_ON) once SW_COLLAPSE is cleared; the SMMU vote
// clock runs once it is enabled. Writes are logged as "w <window> <offset> <value>".
static uint32_t regs[5][0x10000 / 4];
static int cx_responds = 1;
static int rd(void *c, unsigned w, uint32_t off, uint32_t *out) {*out = regs[w][off / 4]; return 0;}
static int wr(void *c, unsigned w, uint32_t off, uint32_t v) {
    printf("w %u %#x %#x\n", w, off, v);
    regs[w][off / 4] = v;
    if (w == GPB_WIN_GPUCC && off == GPB_CC_CX_GDSCR && !(v & GPB_GDSC_SW_COLLAPSE) && cx_responds) {
        regs[w][GPB_CC_CX_GDS_HW_CTRL / 4] |= GPB_GDSC_PWR_ON;
        regs[w][off / 4] |= GPB_GDSC_PWR_ON;
    }
    if (w == GPB_WIN_GPUCC && off == GPB_CC_SMMU_VOTE_CLK && (v & GPB_CBCR_ENABLE)) regs[w][off / 4] &= ~GPB_CBCR_CLK_OFF;
    if (w == GPB_WIN_GPUCC && off == GPB_CC_AHB_CLK && (v & GPB_CBCR_ENABLE)) regs[w][off / 4] &= ~GPB_CBCR_CLK_OFF;
    return 0;
}
// args: mode cfg_ahb cx_gdscr gx_gdscr cx_responds
int main(int argc, char **argv) {
    unsigned mode = strtoul(argv[1], 0, 0);
    regs[GPB_WIN_GCC_GPU][GPB_GCC_GPU_CFG_AHB / 4] = strtoul(argv[2], 0, 0);
    regs[GPB_WIN_GPUCC][GPB_CC_CX_GDSCR / 4] = strtoul(argv[3], 0, 0);
    regs[GPB_WIN_GPUCC][GPB_CC_GX_GDSCR / 4] = strtoul(argv[4], 0, 0);
    cx_responds = atoi(argv[5]);
    regs[GPB_WIN_GPUCC][GPB_CC_AHB_CLK / 4] = GPB_CBCR_CLK_OFF;
    regs[GPB_WIN_GPUCC][GPB_CC_SMMU_VOTE_CLK / 4] = GPB_CBCR_CLK_OFF;
    regs[GPB_WIN_SMMU][GPB_SMMU_ID0 / 4] = 4;
    regs[GPB_WIN_SMMU][GPB_SMMU_SMR(2) / 4] = 0x80000005u;
    regs[GPB_WIN_GPU][GPB_RBBM_STATUS_BYTES / 4] = 0x1234;
    struct gpb_io io = {0, rd, wr, 0};
    struct gpb_result r;
    gpb_run(&io, mode, 0x1f, &r);
    printf("r gcc %s cc %s smmu %s gpu %s cx %#x powered %u clocks %u smr %u first %u rbbm %#x io %d\n", gpb_state_text(r.gcc),
           gpb_state_text(r.cc), gpb_state_text(r.smmu), gpb_state_text(r.gpu), r.cx_gdscr, r.powered_cx, r.powered_clocks,
           r.smr_valid, r.smr_first, r.rbbm_status, r.io_error);
}
'''


class GpuPowerBoardTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which('clang') or shutil.which('gcc')
        if not compiler:
            raise unittest.SkipTest('no host C compiler')
        cls.dir = tempfile.TemporaryDirectory()
        source = Path(cls.dir.name) / 'driver.c'
        source.write_text(DRIVER)
        cls.binary = Path(cls.dir.name) / 'driver'
        subprocess.run([compiler, '-std=c11', '-O1', '-I', str(ROOT / 'package'), str(source), '-o', str(cls.binary)], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def run_board(self, mode, cfg_ahb, cx, gx, responds=1):
        out = subprocess.run([str(self.binary), str(mode), hex(cfg_ahb), hex(cx), hex(gx), str(responds)], check=True,
                             capture_output=True, text=True).stdout.splitlines()
        writes = [tuple(int(v, 0) for v in line.split()[1:]) for line in out if line.startswith('w ')]
        result = next(line.split()[1:] for line in out if line.startswith('r '))
        return writes, dict(zip(result[::2], result[1::2]))

    def test_mode_1_never_writes(self):
        writes, r = self.run_board(1, 0, 0, 0)
        self.assertEqual(writes, [])
        self.assertEqual((r['gcc'], r['cc']), ('ok', 'skip'))

    def test_mode_1_reads_gpucc_when_its_clock_is_enabled_and_gates_the_rest_on_power(self):
        writes, r = self.run_board(1, 1, 0, 0)
        self.assertEqual(writes, [])
        self.assertEqual((r['cc'], r['smmu'], r['gpu']), ('ok', 'skip', 'skip'))

    def test_mode_2_enables_only_the_cfg_ahb_clock(self):
        writes, r = self.run_board(2, 0x80000000, 0, 0)
        self.assertEqual(writes, [(0, 0x004, 0x80000001)])
        self.assertEqual(r['cc'], 'ok')

    def test_mode_3_powers_cx_with_the_stock_sequence(self):
        writes, r = self.run_board(3, 1, GPB_SW_COLLAPSE | 0x6 | 0x2000, 0)
        gdscr = [v for w, off, v in writes if (w, off) == (2, 0x106c)]
        # gdsc_probe: HW_CONTROL and SW_OVERRIDE cleared, CLK_DIS_WAIT 8; gdsc_enable: SW_COLLAPSE cleared, then RETAIN_FF.
        self.assertEqual(gdscr[0], 0x8001)
        self.assertEqual(gdscr[1], 0x8000)
        self.assertTrue(gdscr[2] & (1 << 11))
        self.assertEqual(r['powered'], '1')
        self.assertEqual(r['smmu'], 'ok')
        self.assertEqual((r['smr'], r['first']), ('1', '2'))
        # GX stays off and is never written, so the GPU window is not read.
        self.assertFalse(any((w, off) == (2, 0x100c) for w, off, v in writes))
        self.assertEqual(r['gpu'], 'skip')

    def test_mode_3_reports_a_cx_that_never_comes_on(self):
        writes, r = self.run_board(3, 1, GPB_SW_COLLAPSE, 0, responds=0)
        self.assertEqual(r['powered'], '0')
        self.assertEqual(r['smmu'], 'skip')
        self.assertFalse(any(off == 0x5000 for w, off, v in writes))

    def test_gpu_window_is_read_only_with_cx_and_gx_on(self):
        writes, r = self.run_board(1, 1, 1 << 31, 1 << 31)
        self.assertEqual(r['gpu'], 'ok')
        self.assertEqual(r['rbbm'], '0x1234')


GPB_SW_COLLAPSE = 1

if __name__ == '__main__':
    unittest.main()
