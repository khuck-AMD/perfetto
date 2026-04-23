/*
 * Copyright (C) 2024 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "src/trace_redaction/collect_trace_time_range.h"

#include <algorithm>
#include <cstdint>

#include "perfetto/base/logging.h"
#include "perfetto/base/status.h"
#include "src/trace_redaction/redactor_clock_converter.h"

namespace perfetto::trace_redaction {

base::Status CollectTraceTimeRange::Collect(
    const protos::pbzero::TracePacket::Decoder& packet,
    Context* context) const {
  // Skip packets without timestamps (metadata packets)
  if (!packet.has_timestamp()) {
    return base::OkStatus();
  }

  int64_t raw_ts = static_cast<int64_t>(packet.timestamp());

  // Skip packets with timestamp=0 and no clock_id - these are likely
  // uninitialized metadata packets, not real timestamped events.
  if (raw_ts == 0 && !packet.has_timestamp_clock_id()) {
    return base::OkStatus();
  }

  // Only use packets WITH clock_id for trace time range calculation.
  // Packets without clock_id may use a different clock domain (e.g., MONOTONIC
  // vs BOOTTIME) and would corrupt our extraction window calculation.
  if (!packet.has_timestamp_clock_id()) {
    return base::OkStatus();
  }

  int64_t ts = raw_ts;

  // Try to convert to trace time using clock snapshots
  auto clock_id = ClockId::Machine(packet.timestamp_clock_id());
  auto result = context->clock_converter.ConvertToTrace(
      clock_id, static_cast<uint64_t>(raw_ts));
  if (result.ok()) {
    ts = static_cast<int64_t>(*result);
  }
  // If conversion fails, use raw timestamp

  // Update min/max timestamps
  auto& config = context->time_extraction;
  config.trace_start_ns = std::min(config.trace_start_ns, ts);
  config.trace_end_ns = std::max(config.trace_end_ns, ts);

  return base::OkStatus();
}

base::Status BuildExtractionWindow::Build(Context* context) const {
  auto& config = context->time_extraction;

  // Check if we found any timestamps
  if (config.trace_start_ns == std::numeric_limits<int64_t>::max()) {
    return base::ErrStatus(
        "BuildExtractionWindow: No timestamps found in trace");
  }

  // Compute extraction window
  config.extraction_start_ns = config.trace_start_ns + config.offset_ns;

  if (config.duration_ns > 0) {
    config.extraction_end_ns =
        config.extraction_start_ns + config.duration_ns;
  } else {
    // No duration specified, extract until end of trace
    config.extraction_end_ns = config.trace_end_ns;
  }

  // Clamp to trace bounds
  config.extraction_start_ns =
      std::max(config.extraction_start_ns, config.trace_start_ns);
  config.extraction_end_ns =
      std::min(config.extraction_end_ns, config.trace_end_ns);

  // Validate the window
  if (config.extraction_start_ns > config.extraction_end_ns) {
    return base::ErrStatus(
        "BuildExtractionWindow: Invalid extraction window - start (%lld) > end "
        "(%lld)",
        static_cast<long long>(config.extraction_start_ns),
        static_cast<long long>(config.extraction_end_ns));
  }

  return base::OkStatus();
}

}  // namespace perfetto::trace_redaction
