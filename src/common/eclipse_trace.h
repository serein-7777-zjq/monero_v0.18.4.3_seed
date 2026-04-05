// Copyright (c) 2026
// SPDX-License-Identifier: BSD-3-Clause
//
// Optional JSONL trace for eclipse / USS experiments (ECLIPSE_TRACE).

#pragma once

#include <cstdint>
#include <string>

namespace eclipse_trace
{

#ifdef ECLIPSE_TRACE

void set_data_dir(const std::string &dir);

/** USS_TRIGGER: once per update_sync_search() invocation. */
void uss_trigger(
  bool fired,
  unsigned n_out,
  unsigned n_syncing,
  unsigned n_normal,
  const std::string *dropped_ip,   // nullptr if !fired
  uint16_t dropped_port,
  int64_t dropped_age_s
);

void uss_notify_drop();

void uss_select(
  unsigned n_out,
  const char *path,
  size_t candidates_raw,
  size_t candidates_filtered,
  const std::string &selected_ip,
  uint16_t selected_port
);

void uss_result(
  const std::string &peer_ip,
  uint16_t peer_port,
  bool success,
  const char *result,
  bool gray_attempt
);

void gray_housekeeping(
  size_t graylist_size,
  const std::string &selected_ip,
  uint16_t selected_port,
  const char *probe_result,
  bool promoted_to_whitelist,
  bool entry_removed_from_graylist
);

int consec_gray_fail_value();
void consec_gray_fail_bump();
void consec_gray_fail_reset();

#else

inline void set_data_dir(const std::string &) {}
inline void uss_trigger(bool, unsigned, unsigned, unsigned, const std::string *, uint16_t, int64_t) {}
inline void uss_notify_drop() {}
inline void uss_select(unsigned, const char *, size_t, size_t, const std::string &, uint16_t) {}
inline void uss_result(const std::string &, uint16_t, bool, const char *, bool) {}
inline void gray_housekeeping(size_t, const std::string &, uint16_t, const char *, bool, bool) {}
inline int consec_gray_fail_value() { return 0; }
inline void consec_gray_fail_bump() {}
inline void consec_gray_fail_reset() {}

#endif

} // namespace eclipse_trace
