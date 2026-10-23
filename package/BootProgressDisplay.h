// SPDX-License-Identifier: MIT
#ifndef SHENG_BOOT_PROGRESS_DISPLAY_H
#define SHENG_BOOT_PROGRESS_DISPLAY_H
#include "Font.h"
static const uint64_t font[] = GLYPH_FONT;
struct bp_display {
  uintptr_t frame;
  unsigned bound, width, height, stride, scale;
  unsigned yield_requested;
  char previous[48][BP_COLS];
  uint32_t colors[48][2];
};
static void bp_clear(struct bp_display *d) {
  if (!d->bound) return;
  for(unsigned y=0;y<d->height;++y) {
    if (__atomic_load_n(&d->yield_requested,__ATOMIC_ACQUIRE)) return;
    for(unsigned x=0;x<d->width;++x)
      *(volatile uint32_t *)(d->frame+(uintptr_t)y*d->stride+x*4)=0;
  }
}
// Draw one text row on a background colour. Only the character cells that differ from the row's previous text are
// stored, so a scrolling log or a changing counter costs the changed cells, not the whole 120-column row; a colour change
// repaints the row.
static void bp_line_bg(struct bp_display *d, unsigned row, const char *text, uint32_t color, uint32_t background) {
  if (__atomic_load_n(&d->yield_requested,__ATOMIC_ACQUIRE)) return;
  if (!d->bound || row >= 48 || (row+1)*14*d->scale >= d->height) return;
  unsigned cols = d->width / (6*d->scale);
  if (cols >= BP_COLS) cols = BP_COLS-1;
  // Cache is only an output optimization. All framebuffer stores are bounded
  // by the supplied existing mapping's geometry, including padded rows.
  int recolor = d->colors[row][0] != color || d->colors[row][1] != background;
  if (!recolor && !strcmp(d->previous[row], text)) return;
  char old[BP_COLS];
  bp_copy(old, d->previous[row]);
  bp_copy(d->previous[row], text);
  d->colors[row][0] = color; d->colors[row][1] = background;
  unsigned len = (unsigned)strlen(text), old_len = (unsigned)strlen(old);
  for (unsigned x = 0; x < cols; ++x) {
    unsigned c = x < len ? (unsigned char)text[x] : ' ';
    unsigned was = x < old_len ? (unsigned char)old[x] : ' ';
    if (!recolor && c == was) continue;
    if (c < 32 || c > 126) c = '?';
    uint64_t glyph = font[c-32];
    for (unsigned y = 0; y < 14; ++y) {
      // Font.h stores the first six rows in the high word.
      unsigned bits = y < 6 ? (unsigned)(glyph >> (32+y*5)) :
                      y < 12 ? (unsigned)(glyph >> ((y-6)*5)) : 0;
      for (unsigned dx = 0; dx < 6; ++dx)
        for (unsigned sy = 0; sy < d->scale; ++sy)
          for (unsigned sx = 0; sx < d->scale; ++sx) {
            uintptr_t at = d->frame + (uintptr_t)(row*14*d->scale+y*d->scale+sy)*d->stride +
                           (x*6*d->scale+dx*d->scale+sx)*4;
            *(volatile uint32_t *)at = dx < 5 && ((bits >> dx)&1) ? color : background;
          }
    }
  }
}
static void bp_line(struct bp_display *d, unsigned row, const char *text, uint32_t color) {
  bp_line_bg(d, row, text, color, 0);
}
#endif
