"""Host tests of package/HeatTouch.h: synthetic fingers on a 21 x 30 heat grid, built with the host C++ compiler."""
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

DRIVER = r'''
#include "HeatTouch.h"
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// Each argument is one frame: fingers "row,col,depth;row,col,depth" (cell units; depth in bytes below 180), "-" for none.
int main(int argc, char **argv) {
    // "stretch <mm> <radius>": RunStretching along the columns (0..120.20 mm).
    if (argc == 4 && !strcmp(argv[1], "stretch")) {
        printf("%.3f\n", heat::stretch(atof(argv[2]), heat::kActiveColumn, atof(argv[3]), heat::kStretchColT, heat::kStretchColO));
        return 0;
    }
    heat::Tracker tracker;
    for (int a = 1; a < argc; ++a) {
        uint8_t cells[heat::kCells];
        memset(cells, 180, sizeof cells);
        if (strcmp(argv[a], "-")) {
            for (char *f = strtok(argv[a], ";"); f; f = strtok(nullptr, ";")) {
                float r, c, d;
                sscanf(f, "%f,%f,%f", &r, &c, &d);
                for (int i = 0; i < heat::kCells; ++i) {
                    const float dr = i / heat::kCols - r, dc = i % heat::kCols - c;
                    const int v = cells[i] - (int)(d * expf(-(dr * dr + dc * dc) / 1.2f));
                    cells[i] = (uint8_t)(v < 0 ? 0 : v);
                }
            }
        }
        heat::Contact found[heat::kMaxContacts], out[heat::kMaxContacts];
        const int n = heat::detect(cells, found);
        const int m = tracker.update(found, n, out);
        printf("frame %d detected %d reported %d", a, n, m);
        for (int i = 0; i < m; ++i) printf(" %d:%.2f,%.2f", out[i].id, out[i].x, out[i].y);
        printf("\n");
    }
}
'''


class HeatTouchTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which('clang++') or shutil.which('g++')
        if not compiler:
            raise unittest.SkipTest('no host C++ compiler')
        cls.dir = tempfile.TemporaryDirectory()
        source = Path(cls.dir.name) / 'driver.cpp'
        source.write_text(DRIVER)
        cls.binary = Path(cls.dir.name) / 'driver'
        subprocess.run([compiler, '-std=c++17', '-O1', '-I', str(ROOT / 'package'), str(source), '-o', str(cls.binary)],
                       check=True)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def run_frames(self, *frames):
        result = subprocess.run([str(self.binary), *frames], check=True, capture_output=True, text=True)
        return [line.split() for line in result.stdout.splitlines()]

    @staticmethod
    def contacts(line):
        return [(int(item.split(':')[0]), *map(float, item.split(':')[1].split(','))) for item in line[6:]]

    def test_idle_frame_has_no_contacts(self):
        self.assertEqual(self.run_frames('-')[0][:6], ['frame', '1', 'detected', '0', 'reported', '0'])

    def test_finger_reported_from_second_frame_at_its_centre(self):
        lines = self.run_frames('10,15,60', '10,15,60')
        self.assertEqual(lines[0][3], '1')
        self.assertEqual(lines[0][5], '0')
        (contact,) = self.contacts(lines[1])
        # x along the columns, y along the rows: cell * pitch minus the centring offset.
        self.assertAlmostEqual(contact[1], 15 * 117.67 / 29 + (120.20 - 117.67) / 2, delta=0.3)
        self.assertAlmostEqual(contact[2], 10 * 81.15 / 20 + (85.18 - 81.15) / 2, delta=0.3)

    def test_sub_cell_position(self):
        lines = self.run_frames('10.5,15.5,60', '10.5,15.5,60')
        (contact,) = self.contacts(lines[1])
        self.assertAlmostEqual(contact[1], 15.5 * 117.67 / 29 + (120.20 - 117.67) / 2, delta=0.6)

    def test_drag_keeps_its_id_and_lift_ends_it(self):
        lines = self.run_frames('10,5,60', '10,6,60', '10,7,60', '10,8,60', '-')
        ids = {c[0] for line in lines[1:4] for c in self.contacts(line)}
        self.assertEqual(len(ids), 1)
        self.assertEqual(lines[4][5], '0')

    def test_two_fingers_two_ids(self):
        lines = self.run_frames('5,5,60;15,25,60', '5,5,60;15,25,60')
        contacts = self.contacts(lines[1])
        self.assertEqual(len(contacts), 2)
        self.assertNotEqual(contacts[0][0], contacts[1][0])

    def stretch(self, mm, radius):
        result = subprocess.run([str(self.binary), 'stretch', str(mm), str(radius)], check=True, capture_output=True, text=True)
        return float(result.stdout)

    def test_stretching_spreads_the_border_band(self):
        # rad 5: b = 4.89, o' = 2.6919. o' maps to the edge, b stays, a point between moves outward, beyond b nothing moves.
        self.assertAlmostEqual(self.stretch(120.20 - 2.6919, 5), 120.20, delta=0.01)
        self.assertAlmostEqual(self.stretch(120.20 - 4.89, 5), 120.20 - 4.89, delta=0.01)
        self.assertGreater(self.stretch(120.20 - 3.5, 5), 120.20 - 3.5)
        self.assertAlmostEqual(self.stretch(2.6919, 5), 0, delta=0.01)
        self.assertEqual(self.stretch(60, 5), 60)

    def test_mid_panel_finger_is_not_stretched(self):
        lines = self.run_frames('10,15,60', '10,15,60')
        (contact,) = self.contacts(lines[1])
        self.assertAlmostEqual(contact[1], 15 * 117.67 / 29 + (120.20 - 117.67) / 2, delta=0.3)

    def test_weak_noise_is_ignored(self):
        self.assertEqual(self.run_frames('10,15,12', '10,15,12')[1][5], '0')

    def test_palm_is_not_a_finger(self):
        palm = ';'.join(f'{r},{c},70' for r in range(4, 14, 2) for c in range(8, 22, 2))
        self.assertEqual(self.run_frames(palm, palm)[1][5], '0')


if __name__ == '__main__':
    unittest.main()
