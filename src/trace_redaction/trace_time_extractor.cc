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

#include "src/trace_redaction/trace_time_extractor.h"

#include <memory>
#include <string_view>

#include "perfetto/base/logging.h"
#include "perfetto/base/status.h"
#include "src/trace_redaction/collect_clocks.h"
#include "src/trace_redaction/collect_trace_time_range.h"
#include "src/trace_redaction/filter_by_time_range.h"
#include "src/trace_redaction/trace_redaction_framework.h"
#include "src/trace_redaction/trace_redactor.h"

namespace perfetto::trace_redaction {

// A tolerant version of CollectClocks that logs errors but continues.
// This is needed for merged traces where clock snapshots may not be monotonic.
class TolerantCollectClocks : public CollectClocks {
 public:
  ~TolerantCollectClocks() override;

  base::Status Collect(const protos::pbzero::TracePacket::Decoder& packet,
                       Context* context) const override {
    auto status = CollectClocks::Collect(packet, context);
    if (!status.ok()) {
      // Log the error but continue - we'll use raw timestamps as fallback
      PERFETTO_LOG(
          "Clock collection warning (continuing with raw timestamps): %s",
          status.c_message());
    }
    return base::OkStatus();
  }
};

TolerantCollectClocks::~TolerantCollectClocks() = default;

TraceTimeExtractor::TraceTimeExtractor() = default;

TraceTimeExtractor::~TraceTimeExtractor() = default;

std::unique_ptr<TraceTimeExtractor> TraceTimeExtractor::Create(
    const TimeExtractionConfig& config) {
  auto extractor =
      std::unique_ptr<TraceTimeExtractor>(new TraceTimeExtractor());
  extractor->config_ = config;

  // Create the underlying redactor with our custom primitives
  extractor->redactor_ = std::make_unique<TraceRedactor>();

  // Step 1: Collect clock snapshots for timestamp conversion
  // This must come first so that clock conversion is available for other
  // collectors. We use a tolerant version that continues on errors (e.g.,
  // for merged traces with non-monotonic clock snapshots).
  extractor->redactor_->emplace_collect<TolerantCollectClocks>();

  // Step 2: Collect trace time range (min/max timestamps)
  extractor->redactor_->emplace_collect<CollectTraceTimeRange>();

  // Step 3: Collect slice boundaries for boundary-crossing detection
  extractor->redactor_->emplace_collect<CollectSliceBoundaries>();

  // Build phase: Compute extraction window
  extractor->redactor_->emplace_build<BuildExtractionWindow>();

  // Build phase: Analyze slice boundaries
  extractor->redactor_->emplace_build<BuildSliceBoundaryInfo>();

  // Transform phase: Filter packets by time range
  extractor->redactor_->emplace_transform<FilterByTimeRange>();

  return extractor;
}

base::Status TraceTimeExtractor::Extract(std::string_view source_filename,
                                         std::string_view dest_filename,
                                         Context* context) {
  PERFETTO_DCHECK(redactor_);
  PERFETTO_DCHECK(context);

  // Copy the extraction config into the context so primitives can access it
  context->time_extraction = config_;

  auto status = redactor_->Redact(source_filename, dest_filename, context);

  // Copy back the updated config (with computed values) for inspection
  config_ = context->time_extraction;

  return status;
}

}  // namespace perfetto::trace_redaction
