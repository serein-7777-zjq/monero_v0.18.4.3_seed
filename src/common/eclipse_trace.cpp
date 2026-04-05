// Copyright (c) 2026
// SPDX-License-Identifier: BSD-3-Clause

#include "eclipse_trace.h"

#ifdef ECLIPSE_TRACE

#include <chrono>
#include <cstdio>
#include <fstream>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <atomic>

namespace eclipse_trace
{

namespace
{
  std::mutex g_mutex;
  std::string g_data_dir;
  std::atomic<bool> g_uss_pending_replace{false};
  std::atomic<bool> g_uss_awaiting_result{false};
  std::atomic<int> g_consec_gray_fail{0};

  static std::string json_escape(const std::string &s)
  {
    std::string o;
    o.reserve(s.size() + 8);
    for (char c : s)
    {
      if (c == '"' || c == '\\')
        o += '\\';
      o += c;
    }
    return o;
  }

  static std::string iso8601_utc_now_ms()
  {
    using namespace std::chrono;
    const auto now = system_clock::now();
    const time_t t = system_clock::to_time_t(now);
    const auto ms = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;
    struct tm tm{};
#if defined(_WIN32)
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tm);
    char out[48];
    snprintf(out, sizeof(out), "%s.%03uZ", buf, static_cast<unsigned>(ms.count()));
    return out;
  }

  static void write_line(const std::string &line)
  {
    if (g_data_dir.empty())
      return;
    const std::string path = g_data_dir + "/uss_trace.jsonl";
    std::lock_guard<std::mutex> lock(g_mutex);
    std::ofstream f(path, std::ios::app | std::ios::binary);
    if (!f)
      return;
    f << line << '\n';
  }
}

void set_data_dir(const std::string &dir)
{
  std::lock_guard<std::mutex> lock(g_mutex);
  g_data_dir = dir;
}

void uss_trigger(
  bool fired,
  unsigned n_out,
  unsigned n_syncing,
  unsigned n_normal,
  const std::string *dropped_ip,
  uint16_t dropped_port,
  int64_t dropped_age_s)
{
  std::ostringstream o;
  o << "{\"ts\":\"" << json_escape(iso8601_utc_now_ms()) << "\""
    << ",\"event\":\"USS_TRIGGER\""
    << ",\"fired\":" << (fired ? "true" : "false")
    << ",\"n_out\":" << n_out
    << ",\"n_syncing\":" << n_syncing
    << ",\"n_normal\":" << n_normal;
  if (fired && dropped_ip)
  {
    o << ",\"dropped_ip\":\"" << json_escape(*dropped_ip) << "\""
      << ",\"dropped_port\":" << dropped_port
      << ",\"dropped_age_s\":" << dropped_age_s;
  }
  else
  {
    o << ",\"dropped_ip\":null"
      << ",\"dropped_port\":null"
      << ",\"dropped_age_s\":null";
  }
  o << "}";
  write_line(o.str());
}

void uss_notify_drop()
{
  g_uss_pending_replace.store(true, std::memory_order_release);
}

void uss_select(
  unsigned n_out,
  const char *path,
  size_t candidates_raw,
  size_t candidates_filtered,
  const std::string &selected_ip,
  uint16_t selected_port)
{
  if (!g_uss_pending_replace.load(std::memory_order_acquire))
    return;
  if (g_uss_awaiting_result.load(std::memory_order_acquire))
    return;

  g_uss_awaiting_result.store(true, std::memory_order_release);

  std::ostringstream o;
  o << "{\"ts\":\"" << json_escape(iso8601_utc_now_ms()) << "\""
    << ",\"event\":\"USS_SELECT\""
    << ",\"n_out\":" << n_out
    << ",\"path\":\"" << json_escape(path ? path : "") << "\""
    << ",\"candidates_raw\":" << candidates_raw
    << ",\"candidates_filtered\":" << candidates_filtered
    << ",\"selected_ip\":\"" << json_escape(selected_ip) << "\""
    << ",\"selected_port\":" << selected_port
    << "}";
  write_line(o.str());
}

void uss_result(
  const std::string &peer_ip,
  uint16_t peer_port,
  bool success,
  const char *result,
  bool gray_attempt)
{
  if (!g_uss_awaiting_result.load(std::memory_order_acquire))
    return;
  g_uss_awaiting_result.store(false, std::memory_order_release);

  if (gray_attempt)
  {
    if (success)
      g_consec_gray_fail.store(0, std::memory_order_relaxed);
    else
      g_consec_gray_fail.fetch_add(1, std::memory_order_relaxed);
  }

  if (success)
    g_uss_pending_replace.store(false, std::memory_order_release);

  const int cgf = g_consec_gray_fail.load(std::memory_order_relaxed);

  std::ostringstream o;
  o << "{\"ts\":\"" << json_escape(iso8601_utc_now_ms()) << "\""
    << ",\"event\":\"USS_RESULT\""
    << ",\"peer_ip\":\"" << json_escape(peer_ip) << "\""
    << ",\"peer_port\":" << peer_port
    << ",\"result\":\"" << json_escape(result ? result : "") << "\""
    << ",\"consec_gray_fail\":" << cgf
    << "}";
  write_line(o.str());
}

void gray_housekeeping(
  size_t graylist_size,
  const std::string &selected_ip,
  uint16_t selected_port,
  const char *probe_result,
  bool promoted_to_whitelist,
  bool entry_removed_from_graylist)
{
  std::ostringstream o;
  o << "{\"ts\":\"" << json_escape(iso8601_utc_now_ms()) << "\""
    << ",\"event\":\"GRAY_HOUSEKEEPING\""
    << ",\"graylist_size\":" << graylist_size
    << ",\"selected_ip\":\"" << json_escape(selected_ip) << "\""
    << ",\"selected_port\":" << selected_port
    << ",\"probe_result\":\"" << json_escape(probe_result ? probe_result : "") << "\""
    << ",\"promoted_to_whitelist\":" << (promoted_to_whitelist ? "true" : "false")
    << ",\"entry_removed_from_graylist\":" << (entry_removed_from_graylist ? "true" : "false")
    << "}";
  write_line(o.str());
}

int consec_gray_fail_value()
{
  return g_consec_gray_fail.load(std::memory_order_relaxed);
}

void consec_gray_fail_bump()
{
  g_consec_gray_fail.fetch_add(1, std::memory_order_relaxed);
}

void consec_gray_fail_reset()
{
  g_consec_gray_fail.store(0, std::memory_order_relaxed);
}

} // namespace eclipse_trace

#else

namespace eclipse_trace
{
// ECLIPSE_TRACE disabled: stubs in header; keep TU non-empty for all toolchains.
void eclipse_trace_translation_unit_anchor() {}
}

#endif
