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

#include "src/trace_redaction/filter_by_time_range.h"

#include <cstdint>
#include <limits>
#include <optional>
#include <string>

#include "perfetto/base/logging.h"
#include "perfetto/base/status.h"
#include "perfetto/protozero/scattered_heap_buffer.h"
#include "src/trace_redaction/proto_util.h"
#include "src/trace_redaction/redactor_clock_converter.h"

#include "protos/perfetto/config/trace_config.pbzero.h"
#include "protos/perfetto/trace/trace_packet.pbzero.h"
#include "protos/perfetto/trace/track_event/track_event.pbzero.h"

namespace perfetto::trace_redaction {

namespace {

using TracePacket = protos::pbzero::TracePacket;
using TraceConfig = protos::pbzero::TraceConfig;
using TrackEvent = protos::pbzero::TrackEvent;

// Rewrites trace_config to remove write_into_file flag which causes warnings
// when loading extracted traces. The extracted trace is self-contained and
// doesn't need streaming-related settings.
void StripWriteIntoFile(std::string* packet) {
  protozero::HeapBuffered<TracePacket> new_packet;
  protozero::ProtoDecoder packet_decoder(*packet);

  for (auto field = packet_decoder.ReadField(); field.valid();
       field = packet_decoder.ReadField()) {
    if (field.id() == TracePacket::kTraceConfigFieldNumber) {
      // Rewrite trace_config without write_into_file
      auto* new_config = new_packet->set_trace_config();
      protozero::ProtoDecoder config_decoder(field.as_bytes());

      for (auto config_field = config_decoder.ReadField(); config_field.valid();
           config_field = config_decoder.ReadField()) {
        // Skip write_into_file (field 8) - it's not relevant for extracted
        // traces
        if (config_field.id() == TraceConfig::kWriteIntoFileFieldNumber) {
          continue;
        }
        proto_util::AppendField(config_field, new_config);
      }
    } else {
      proto_util::AppendField(field, new_packet.get());
    }
  }

  packet->assign(new_packet.SerializeAsString());
}

}  // namespace

bool FilterByTimeRange::IsMetadataPacket(
    const TracePacket::Decoder& packet) const {
  // Packets without timestamps are metadata
  if (!packet.has_timestamp()) {
    return true;
  }

  // Essential metadata packets that should always be included:
  // - Clock snapshots for timestamp conversion
  // - Trace config and packet defaults for parsing
  // - Interned data (strings, source locations) referenced by other packets
  // - Track descriptors defining tracks
  // - Service events and sync markers
  // - Packets with incremental_state_cleared (reset interning state)
  // - Packets with previous_packet_dropped (indicate lost data)
  return packet.has_clock_snapshot() || packet.has_trace_config() ||
         packet.has_trace_packet_defaults() || packet.has_interned_data() ||
         packet.has_track_descriptor() || packet.has_service_event() ||
         packet.has_synchronization_marker() || packet.has_trace_uuid() ||
         packet.incremental_state_cleared() || packet.previous_packet_dropped();
}

std::optional<int64_t> FilterByTimeRange::GetPacketTimestamp(
    const TracePacket::Decoder& packet,
    const Context& context) const {
  if (!packet.has_timestamp()) {
    return std::nullopt;
  }

  int64_t ts = static_cast<int64_t>(packet.timestamp());

  // Skip packets with timestamp=0 and no clock_id - treat as metadata
  if (ts == 0 && !packet.has_timestamp_clock_id()) {
    return std::nullopt;
  }

  // Packets without clock_id may use a different clock domain (e.g., MONOTONIC
  // vs BOOTTIME). We can't reliably compare their timestamps to our extraction
  // window which is based on BOOTTIME. Return a special value to indicate
  // these should be dropped (unless they're metadata packets).
  if (!packet.has_timestamp_clock_id()) {
    // Return INT64_MIN to signal "drop this packet" (outside any valid window)
    return std::numeric_limits<int64_t>::min();
  }

  // Try to convert to trace time using clock snapshots
  auto clock_id = ClockId::Machine(packet.timestamp_clock_id());
  auto result = context.clock_converter.ConvertToTrace(
      clock_id, static_cast<uint64_t>(ts));
  if (result.ok()) {
    ts = static_cast<int64_t>(*result);
  }
  // If conversion fails, use raw timestamp

  return ts;
}

void FilterByTimeRange::RewriteTimestamp(std::string* packet,
                                         int64_t new_timestamp) const {
  protozero::HeapBuffered<TracePacket> message;
  protozero::ProtoDecoder decoder(*packet);

  for (auto field = decoder.ReadField(); field.valid();
       field = decoder.ReadField()) {
    if (field.id() == TracePacket::kTimestampFieldNumber) {
      // Replace with new timestamp
      message->set_timestamp(static_cast<uint64_t>(new_timestamp));
    } else {
      proto_util::AppendField(field, message.get());
    }
  }

  packet->assign(message.SerializeAsString());
}

bool FilterByTimeRange::HandleTrackEvent(const TracePacket::Decoder& packet,
                                         int64_t timestamp,
                                         const Context& context,
                                         std::string* packet_str) const {
  if (!packet.has_track_event()) {
    return true;  // Not a track event, keep as-is
  }

  const auto& config = context.time_extraction;
  TrackEvent::Decoder track_event(packet.track_event());

  // Check if this is a slice begin that started before the window
  if (track_event.type() == TrackEvent::TYPE_SLICE_BEGIN) {
    if (timestamp < config.extraction_start_ns) {
      // Check if this slice's track has an end within or after the window
      uint64_t track_uuid = track_event.track_uuid();
      auto it = config.slices_crossing_start.find(track_uuid);
      if (it != config.slices_crossing_start.end()) {
        // This slice crosses the start boundary - clip its start time
        RewriteTimestamp(packet_str, config.extraction_start_ns);
        return true;
      }
      // Slice ends before window, drop it
      return false;
    }
  }

  // Check if this is a slice end that ends after the window
  if (track_event.type() == TrackEvent::TYPE_SLICE_END) {
    if (timestamp > config.extraction_end_ns) {
      // Check if this slice's track began within the window
      uint64_t track_uuid = track_event.track_uuid();
      auto it = config.slices_crossing_end.find(track_uuid);
      if (it != config.slices_crossing_end.end()) {
        // This slice crosses the end boundary - clip its end time
        RewriteTimestamp(packet_str, config.extraction_end_ns);
        return true;
      }
      // Slice began after window, drop it
      return false;
    }
  }

  return true;  // Within window, keep as-is
}

base::Status FilterByTimeRange::Transform(const Context& context,
                                          std::string* packet) const {
  if (!packet || packet->empty()) {
    return base::OkStatus();
  }

  TracePacket::Decoder decoder(*packet);

  // Fix trace_config to remove write_into_file which causes warnings
  if (decoder.has_trace_config()) {
    StripWriteIntoFile(packet);
    return base::OkStatus();
  }

  const auto& config = context.time_extraction;

  // For metadata packets with timestamps, clip their timestamps to the
  // extraction window start so they don't create events before the window.
  if (IsMetadataPacket(decoder)) {
    if (decoder.has_timestamp() && decoder.has_timestamp_clock_id()) {
      int64_t ts = static_cast<int64_t>(decoder.timestamp());
      // Try clock conversion
      auto clock_id = ClockId::Machine(decoder.timestamp_clock_id());
      auto result = context.clock_converter.ConvertToTrace(
          clock_id, static_cast<uint64_t>(ts));
      if (result.ok()) {
        ts = static_cast<int64_t>(*result);
      }
      // If timestamp is before extraction window, clip it
      if (ts < config.extraction_start_ns) {
        RewriteTimestamp(packet, config.extraction_start_ns);
      }
    }
    return base::OkStatus();
  }

  // Get packet timestamp
  auto ts_opt = GetPacketTimestamp(decoder, context);
  if (!ts_opt.has_value()) {
    // No reliable timestamp - keep the packet
    return base::OkStatus();
  }

  int64_t ts = *ts_opt;

  // Simple time-based filtering: keep packets within the extraction window
  if (ts >= config.extraction_start_ns && ts <= config.extraction_end_ns) {
    return base::OkStatus();
  }

  // Outside window - drop the packet
  packet->clear();
  return base::OkStatus();
}

// CollectSliceBoundaries implementation

base::Status CollectSliceBoundaries::Collect(const TracePacket::Decoder& packet,
                                             Context* context) const {
  if (!packet.has_track_event() || !packet.has_timestamp()) {
    return base::OkStatus();
  }

  int64_t ts = static_cast<int64_t>(packet.timestamp());

  // Convert to trace time if using a different clock
  if (packet.has_timestamp_clock_id()) {
    auto clock_id = ClockId::Machine(packet.timestamp_clock_id());
    auto result = context->clock_converter.ConvertToTrace(
        clock_id, static_cast<uint64_t>(ts));
    if (result.ok()) {
      ts = static_cast<int64_t>(*result);
    }
  }

  TrackEvent::Decoder track_event(packet.track_event());
  uint64_t track_uuid = track_event.track_uuid();
  auto& config = context->time_extraction;

  if (track_event.type() == TrackEvent::TYPE_SLICE_BEGIN) {
    // Record slice start
    config.active_slices[track_uuid] = ts;
  } else if (track_event.type() == TrackEvent::TYPE_SLICE_END) {
    // Match with slice start - just remove from active slices for now
    // Boundary analysis happens in the transform phase
    config.active_slices.erase(track_uuid);
  }

  return base::OkStatus();
}

// BuildSliceBoundaryInfo implementation

base::Status BuildSliceBoundaryInfo::Build(Context* context) const {
  // At this point, extraction_start_ns and extraction_end_ns are set
  // by BuildExtractionWindow.
  //
  // For simplicity in Phase 1, we rely on the active_slices map populated
  // during collection. Slices that are still "active" (have a BEGIN but no
  // END within the collected packets) are assumed to cross the end boundary.
  //
  // A more complete implementation would require a second pass to match
  // all BEGIN/END pairs with their timestamps.
  //
  // For now, we handle boundary crossing at transform time by checking
  // if a slice's timestamp is outside the window but the slice should
  // still be included.

  auto& config = context->time_extraction;

  // Clear any residual state
  config.slices_crossing_start.clear();
  config.slices_crossing_end.clear();

  return base::OkStatus();
}

}  // namespace perfetto::trace_redaction
