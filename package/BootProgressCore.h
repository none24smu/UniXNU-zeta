// SPDX-License-Identifier: MIT
// Bounded, allocation-free diagnostic state. No hardware or trust decisions.
#ifndef SHENG_BOOT_PROGRESS_CORE_H
#define SHENG_BOOT_PROGRESS_CORE_H
#define BP_COLS 120
#define BP_LOGS 14
#define BP_HISTORY 6
struct bp_history { unsigned seconds; char text[BP_COLS]; };
struct bp_core {
  unsigned seconds, activity_at, limit, stall, frozen, reason, continuous;
  unsigned log_row, log_col, log_lines, history_count, dropped;
  unsigned long long reads, verified, failures;
  char logs[BP_LOGS][BP_COLS];
  struct bp_history history[BP_HISTORY];
};
static void bp_copy(char *out, const char *in) {
  unsigned n = 0;
  while (n < BP_COLS-1 && in[n]) { out[n] = in[n]; ++n; }
  out[n] = 0;
}
static void bp_stage(struct bp_core *s, const char *text, unsigned now) {
  if (s->frozen) return;
  struct bp_history *h = &s->history[s->history_count++ % BP_HISTORY];
  h->seconds = now; bp_copy(h->text, text); s->activity_at = now;
}
static void bp_char(struct bp_core *s, char c) {
  if (s->frozen || c == '\r') return;
  if (c == '\t') c = ' ';
  if (c != '\n' && (c < 32 || c > 126)) return;
  if (c == '\n' || s->log_col == BP_COLS-1) {
    s->log_row = (s->log_row + 1) % BP_LOGS;
    s->log_col = 0; s->logs[s->log_row][0] = 0; ++s->log_lines;
    if (c == '\n') return;
  }
  s->logs[s->log_row][s->log_col++] = c;
  s->logs[s->log_row][s->log_col] = 0;
}
// Logs/IRQs alone are not useful progress. Repeated I/O is activity, not proof
// of forward progress. Diagnostic mode freezes at a bound; continuous boot
// mode reports the same deadline without suspending the OS or its recorder.
static unsigned bp_poll(struct bp_core *s, unsigned now,
                         unsigned long long reads, unsigned long long verified,
                         unsigned long long failures) {
  if (s->frozen) return s->reason;
  s->seconds = now;
  if (reads != s->reads || verified != s->verified || failures != s->failures)
    s->activity_at = now;
  s->reads = reads; s->verified = verified; s->failures = failures;
  s->reason = 0;
  if (now >= s->limit) s->reason = 2; // observation deadline, not a boot verdict
  else if (now >= s->activity_at && now - s->activity_at >= s->stall) s->reason = 1;
  if (s->reason && !s->continuous) s->frozen = 1;
  return s->reason;
}
#endif
