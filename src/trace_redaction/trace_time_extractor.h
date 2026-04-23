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

#ifndef SRC_TRACE_REDACTION_TRACE_TIME_EXTRACTOR_H_
#define SRC_TRACE_REDACTION_TRACE_TIME_EXTRACTOR_H_

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

#include "perfetto/base/status.h"
#include "src/trace_redaction/time_extraction_config.h"
#include "src/trace_redaction/trace_redaction_framework.h"
#include "src/trace_redaction/trace_redactor.h"

namespace perfetto::trace_redaction {

// TraceTimeExtractor extracts a time segment from an existing Perfetto trace.
//
// Usage:
//   TimeExtractionConfig config;
//   config.offset_ns = 1000000000;  // 1 second offset from trace start
//   config.duration_ns = 5000000000;  // 5 seconds duration
//
//   auto extractor = TraceTimeExtractor::Create(config);
//   Context context;
//   extractor->Extract("input.perfetto-trace", "output.perfetto-trace",
//                      &context);
//
// The extractor will:
// 1. Read the input trace and determine its time range
// 2. Compute the extraction window based on offset and duration
// 3. Filter packets to only include those within the window
// 4. Handle boundary-crossing slice events by clipping their timestamps
// 5. Always include metadata packets (clock snapshots, track descriptors, etc.)
class TraceTimeExtractor {
 public:
  // Creates a new TraceTimeExtractor with the given configuration.
  // The config is copied internally.
  static std::unique_ptr<TraceTimeExtractor> Create(
      const TimeExtractionConfig& config);

  ~TraceTimeExtractor();

  // Extracts a time segment from the source trace and writes it to dest.
  // The context will contain state from the extraction process.
  base::Status Extract(std::string_view source_filename,
                       std::string_view dest_filename,
                       Context* context);

  // Returns the time extraction configuration (after extraction, this will
  // contain the computed extraction window and trace time range).
  const TimeExtractionConfig& config() const { return config_; }

 private:
  TraceTimeExtractor();

  TimeExtractionConfig config_;
  std::unique_ptr<TraceRedactor> redactor_;
};

}  // namespace perfetto::trace_redaction

#endif  // SRC_TRACE_REDACTION_TRACE_TIME_EXTRACTOR_H_
