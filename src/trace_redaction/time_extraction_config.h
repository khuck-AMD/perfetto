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

#ifndef SRC_TRACE_REDACTION_TIME_EXTRACTION_CONFIG_H_
#define SRC_TRACE_REDACTION_TIME_EXTRACTION_CONFIG_H_

#include <cstdint>
#include <limits>
#include <unordered_map>
#include <utility>

namespace perfetto::trace_redaction {

// Configuration and state for time-based trace extraction.
struct TimeExtractionConfig {
  // Input parameters (set by user before extraction)
  int64_t offset_ns = 0;    // Offset from trace start (nanoseconds)
  int64_t duration_ns = 0;  // Duration to extract (nanoseconds), 0 = until end

  // Collected during first pass (collect phase)
  int64_t trace_start_ns = std::numeric_limits<int64_t>::max();
  int64_t trace_end_ns = std::numeric_limits<int64_t>::min();

  // Computed extraction window (in trace time, set during build phase)
  int64_t extraction_start_ns = 0;
  int64_t extraction_end_ns = 0;

  // Tracks active slices for boundary-crossing detection.
  // Maps track_uuid -> slice_start_timestamp
  // Used to identify slices that started before extraction window.
  std::unordered_map<uint64_t, int64_t> active_slices;

  // Slices that cross the extraction start boundary.
  // Maps track_uuid -> original_start_timestamp
  // These slices need their start time clipped to extraction_start_ns.
  std::unordered_map<uint64_t, int64_t> slices_crossing_start;

  // Slices that cross the extraction end boundary.
  // Maps track_uuid -> original_end_timestamp
  // These slices need their end time clipped to extraction_end_ns.
  std::unordered_map<uint64_t, int64_t> slices_crossing_end;

  // Returns true if extraction is enabled (duration > 0 or offset > 0)
  bool IsEnabled() const { return duration_ns > 0 || offset_ns > 0; }

  // Returns true if a timestamp falls within the extraction window
  bool InWindow(int64_t ts) const {
    return ts >= extraction_start_ns && ts <= extraction_end_ns;
  }
};

}  // namespace perfetto::trace_redaction

#endif  // SRC_TRACE_REDACTION_TIME_EXTRACTION_CONFIG_H_
