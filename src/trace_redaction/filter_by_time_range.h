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

#ifndef SRC_TRACE_REDACTION_FILTER_BY_TIME_RANGE_H_
#define SRC_TRACE_REDACTION_FILTER_BY_TIME_RANGE_H_

#include <string>

#include "perfetto/base/status.h"
#include "src/trace_redaction/time_extraction_config.h"
#include "src/trace_redaction/trace_redaction_framework.h"

namespace perfetto::trace_redaction {

// Transform primitive that filters packets based on their timestamp.
//
// Packets are handled as follows:
// - Metadata packets (no timestamp, or essential for trace validity): KEEP
// - Packets with timestamp within extraction window: KEEP
// - Packets with timestamp outside extraction window: DROP
//
// For boundary-crossing slice events:
// - SLICE_BEGIN before window but SLICE_END in window: modify start timestamp
// - SLICE_BEGIN in window but SLICE_END after window: modify end timestamp
class FilterByTimeRange : public TransformPrimitive {
 public:
  base::Status Transform(const Context& context,
                         std::string* packet) const override;

 private:
  // Returns true if the packet is a metadata packet that should always be kept.
  bool IsMetadataPacket(
      const protos::pbzero::TracePacket::Decoder& packet) const;

  // Gets the timestamp from a packet, converting to trace time if needed.
  // Returns std::nullopt if the packet has no timestamp.
  std::optional<int64_t> GetPacketTimestamp(
      const protos::pbzero::TracePacket::Decoder& packet,
      const Context& context) const;

  // Handles track events that may have slice begin/end semantics.
  // Returns true if the packet should be kept (possibly modified).
  bool HandleTrackEvent(const protos::pbzero::TracePacket::Decoder& packet,
                        int64_t timestamp,
                        const Context& context,
                        std::string* packet_str) const;

  // Rewrites the timestamp field in a packet.
  void RewriteTimestamp(std::string* packet, int64_t new_timestamp) const;
};

// Collect primitive that tracks slice begin/end events for boundary detection.
// This must run after CollectClocks so that clock conversion is available.
class CollectSliceBoundaries : public CollectPrimitive {
 public:
  base::Status Collect(const protos::pbzero::TracePacket::Decoder& packet,
                       Context* context) const override;
};

// Build primitive that identifies slices crossing extraction boundaries.
class BuildSliceBoundaryInfo : public BuildPrimitive {
 public:
  base::Status Build(Context* context) const override;
};

}  // namespace perfetto::trace_redaction

#endif  // SRC_TRACE_REDACTION_FILTER_BY_TIME_RANGE_H_
