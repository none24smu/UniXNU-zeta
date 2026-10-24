// SPDX-License-Identifier: BSD-2-Clause-Patent
// Finger contacts from one Surface Duo 2 (zeta) heat grid: the finger path of the stock heat library
// (/vendor/lib64/c1/libsurfacetouch_c1.so, SurfaceHeatProcessorLogic -> TouchDetection -> TrackLib), ported from its
// decompilation with the Zeta tuning (PS_CFG_DATA_Zeta) values it reads. Plain C++, no kernel interfaces, so it builds on
// the host for tests (scripts/tests/test-heat-touch.cpp).
//
// The grid is the panel's 21 x 30 sensors, row-major with 30 cells a row (the Zeta topology record: 21 rows, 30 columns).
// Columns run along the panel's long side, rows along its short side. A byte is a baseline-referenced reading: 180 (0xb4)
// is no touch and lower is stronger.
//
// Ported so far: the signal table, the CCL (8-connected, threshold byte from TouchDetectionCfg's lowest-noise CCL
// threshold), the blob gates and frame aborts, the padded centre of mass (RecalculateComWithPadding), the antenna-to-mm
// conversion (DetectedArray), and nearest-neighbour tracking with the 35 mm limit, reported from the second matched frame.
// Not yet: the noise-adaptive CCL threshold (it needs the per-cycle noise from the metadata frame), the peak split of
// multi-finger blobs, the 4-class LLR classifier (a blob is a finger here when the stock promotion rule's size and peak
// tests pass and it is smaller than the big-blob palm size), edge stretching, border drop, and the Kalman/jitter filters.
#pragma once
#include <stdint.h>

namespace heat {

constexpr int kRows = 21, kCols = 30, kCells = kRows * kCols;
constexpr int kMaxContacts = 10;

// TouchDetection::Init: signal(b) = 1 - (b * 0.0022203543 + 0.6), single precision.
constexpr float kStep = 0.0022203543f;
inline float signal(unsigned b) {return 1.0f - ((float)b * kStep + 0.6f);}

// Zeta values (TouchDetectionCfg = PS_CFG_DATA_Zeta section 0x37, TouchTrackDataCfg = section 0x28).
constexpr float kCclThreshold = 0.04f;       // TDC+0x0 (minimum of the adaptive CCL threshold)
constexpr float kValidPeak = 0.055f;         // TDC+0xc: a 1- or 2-cell blob is valid above this peak
constexpr float kWeakPeak = 0.04f;           // FeatureExtraction: blobs whose peak is below this are dropped
constexpr float kFingerPeak = 0.07f;         // ClassifyTracks: peak a new track needs to become a finger
constexpr unsigned kMaxTouched = 700;        // TDC+0xb6: more touched cells drop the frame
constexpr unsigned kMaxBlobCells = 300;      // TDC+0xb4: a blob this large drops the frame
constexpr unsigned kPalmCells = 50;          // TDC+0xe80: big-blob (palm) shortcut
constexpr unsigned kPaddedComCells = 30;     // RecalculateComWithPadding handles blobs up to this size
constexpr unsigned kPaddingBaseByte = 178;   // TTS+8: padding weight base, signal(178)
constexpr float kPaddingPeakShare = 0.20f;   // TTC+0x8 = 20 (%): padding ring cells must exceed this share of the peak
// DetectedArray: mm = cell * pitch - (physical - active) / 2, clamped to the active area (StaticConfig sizes, 0.01 mm).
constexpr float kPitchColumn = 117.67f / 29, kPitchRow = 81.15f / 20;
constexpr float kActiveColumn = 120.20f, kActiveRow = 85.18f;
constexpr float kOffsetColumn = (117.67f - 120.20f) / 2, kOffsetRow = (81.15f - 85.18f) / 2;
constexpr float kMatchLimit = 35.0f;         // TouchDetection's Hungarian cost cap, mm

struct Contact {
    float x, y;      // mm on the panel: x along the 30 columns (long side, 0..120.20), y along the 21 rows (short side, 0..85.18)
    int id;          // tracking id, stable while the finger stays down
};

inline int byteThreshold(float threshold) {return (int)(((1.0f - threshold) - 0.6f) / kStep + 0.5f);}

// One frame: up to kMaxContacts fingers (positions in mm, no ids). Returns the count, or 0 when the frame is dropped.
inline int detect(const uint8_t *cells, Contact *out) {
    const int on = byteThreshold(kCclThreshold);
    uint8_t label[kCells] = {};
    unsigned touched = 0;
    for (int i = 0; i < kCells; ++i) touched += cells[i] <= on;
    if (touched >= kMaxTouched) return 0;
    struct Blob {unsigned count; int minR, minC, maxR, maxC; unsigned peak; float w, wr, wc;};
    Blob blobs[48];
    int nblobs = 0;
    int16_t stack[kCells];
    for (int start = 0; start < kCells; ++start) {
        if (label[start] || cells[start] > on) continue;
        if (nblobs == 48) break;
        Blob &b = blobs[nblobs++];
        b = {0, kRows, kCols, -1, -1, 255, 0, 0, 0};
        const uint8_t id = (uint8_t)nblobs;
        int top = 0;
        stack[top++] = (int16_t)start;
        label[start] = id;
        while (top) {
            const int at = stack[--top], r = at / kCols, c = at % kCols;
            const float s = signal(cells[at]);
            float w = s - (kCclThreshold - kStep);
            if (w <= 0.0001f) w = 0.0001f;
            b.w += w; b.wr += w * r; b.wc += w * c;
            ++b.count;
            if (r < b.minR) b.minR = r;
            if (r > b.maxR) b.maxR = r;
            if (c < b.minC) b.minC = c;
            if (c > b.maxC) b.maxC = c;
            if (cells[at] < b.peak) b.peak = cells[at];
            for (int dr = -1; dr <= 1; ++dr)
                for (int dc = -1; dc <= 1; ++dc) {
                    const int rr = r + dr, cc = c + dc;
                    if ((dr || dc) && rr >= 0 && rr < kRows && cc >= 0 && cc < kCols) {
                        const int n = rr * kCols + cc;
                        if (!label[n] && cells[n] <= on) {label[n] = id; stack[top++] = (int16_t)n;}
                    }
                }
        }
        if (b.count >= kMaxBlobCells) return 0;
    }
    const float base = signal(kPaddingBaseByte);
    int count = 0;
    for (int i = 0; i < nblobs && count < kMaxContacts; ++i) {
        const Blob &b = blobs[i];
        const float peak = signal(b.peak);
        if (!(b.count > 2 || peak > kValidPeak) || peak < kWeakPeak) continue;
        if (b.count >= kPalmCells || b.count < 2 || peak <= kFingerPeak) continue;
        float r = b.wr / b.w, c = b.wc / b.w;
        if (b.count <= kPaddedComCells) {
            // The blob's own cells and the 4-neighbours of its cells above padThr that no blob owns, weighted s - base.
            const uint8_t id = (uint8_t)(i + 1);
            const float padThr = peak * kPaddingPeakShare;
            float w = 0, wr = 0, wc = 0;
            for (int rr = b.minR - 1; rr <= b.maxR + 1; ++rr)
                for (int cc = b.minC - 1; cc <= b.maxC + 1; ++cc) {
                    if (rr < 0 || rr >= kRows || cc < 0 || cc >= kCols) continue;
                    const int at = rr * kCols + cc;
                    const float s = signal(cells[at]);
                    bool use = label[at] == id;
                    if (!use && !label[at] && s > base) {
                        static const int kNear[4][2] = {{-1, 0}, {1, 0}, {0, -1}, {0, 1}};
                        for (const auto &d : kNear) {
                            const int nr = rr + d[0], nc = cc + d[1];
                            if (nr < 0 || nr >= kRows || nc < 0 || nc >= kCols) continue;
                            const int n = nr * kCols + nc;
                            if (label[n] == id && signal(cells[n]) > padThr) {use = true; break;}
                        }
                    }
                    if (!use) continue;
                    w += s - base; wr += (s - base) * rr; wc += (s - base) * cc;
                }
            if (w > 0) {r = wr / w; c = wc / w;}
        }
        float x = c * kPitchColumn - kOffsetColumn, y = r * kPitchRow - kOffsetRow;
        x = x < 0 ? 0 : x > kActiveColumn ? kActiveColumn : x;
        y = y < 0 ? 0 : y > kActiveRow ? kActiveRow : y;
        out[count++] = {x, y, -1};
    }
    return count;
}

// One panel's tracks: each detected finger takes the nearest unclaimed track within the match limit, the rest open new
// tracks; a track is reported from its second matched frame (TrackLib) and dropped when no finger matches it.
struct Tracker {
    struct Track {float x, y; int id; unsigned age;};
    Track tracks[kMaxContacts] = {};
    int count = 0, nextId = 0;
    // Returns the reported contacts in out.
    int update(const Contact *found, int nfound, Contact *out) {
        Track next[kMaxContacts];
        int nnext = 0;
        bool claimed[kMaxContacts] = {};
        for (int i = 0; i < nfound && nnext < kMaxContacts; ++i) {
            int best = -1;
            float bestD = kMatchLimit * kMatchLimit;
            for (int t = 0; t < count; ++t) {
                const float dx = tracks[t].x - found[i].x, dy = tracks[t].y - found[i].y, d = dx * dx + dy * dy;
                if (!claimed[t] && d < bestD) {bestD = d; best = t;}
            }
            if (best >= 0) {
                claimed[best] = true;
                next[nnext++] = {found[i].x, found[i].y, tracks[best].id, tracks[best].age + 1};
            } else {
                next[nnext++] = {found[i].x, found[i].y, nextId, 0};
                nextId = (nextId + 1) & 15;
            }
        }
        for (int t = 0; t < nnext; ++t) tracks[t] = next[t];
        count = nnext;
        int reported = 0;
        for (int t = 0; t < count; ++t)
            if (tracks[t].age >= 1) out[reported++] = {tracks[t].x, tracks[t].y, tracks[t].id};
        return reported;
    }
};

}  // namespace heat
