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

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "perfetto/base/logging.h"
#include "src/trace_redaction/time_extraction_config.h"
#include "src/trace_redaction/trace_redaction_framework.h"
#include "src/trace_redaction/trace_time_extractor.h"

namespace {

void PrintUsage(const char* prog_name) {
  fprintf(stderr,
          R"(
Usage: %s [OPTIONS] <input_trace> <output_trace>

Extract a time segment from a Perfetto trace.

OPTIONS:
  --offset <nanoseconds>    Offset from trace start (default: 0)
  --offset-ms <milliseconds> Offset from trace start in milliseconds
  --offset-s <seconds>      Offset from trace start in seconds

  --duration <nanoseconds>  Duration to extract (default: until end of trace)
  --duration-ms <milliseconds> Duration to extract in milliseconds
  --duration-s <seconds>    Duration to extract in seconds

  --help                    Show this help message

EXAMPLES:
  # Extract from 1 second into the trace, for 5 seconds
  %s --offset-s 1 --duration-s 5 input.perfetto-trace output.perfetto-trace

  # Extract the first 10 seconds of the trace
  %s --duration-s 10 input.perfetto-trace output.perfetto-trace

  # Extract starting at 500ms offset, for 2 seconds
  %s --offset-ms 500 --duration-ms 2000 input.perfetto-trace output.perfetto-trace

NOTES:
  - Metadata packets (clock snapshots, track descriptors, etc.) are always
    included regardless of their timestamp.
  - Slices that cross extraction boundaries will have their timestamps
    clipped to the extraction window.
  - Ftrace events are filtered at the bundle level based on the bundle
    timestamp.
)",
          prog_name, prog_name, prog_name, prog_name);
}

int64_t ParseInt64OrDie(const char* str, const char* arg_name) {
  char* end;
  int64_t value = strtoll(str, &end, 10);
  if (*end != '\0') {
    PERFETTO_ELOG("Invalid value for %s: %s", arg_name, str);
    exit(1);
  }
  return value;
}

constexpr int64_t kNsPerMs = 1000000LL;
constexpr int64_t kNsPerS = 1000000000LL;

}  // namespace

int main(int argc, char** argv) {
  perfetto::trace_redaction::TimeExtractionConfig config;
  const char* input_file = nullptr;
  const char* output_file = nullptr;

  for (int i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
      PrintUsage(argv[0]);
      return 0;
    } else if (strcmp(argv[i], "--offset") == 0) {
      if (++i >= argc) {
        PERFETTO_ELOG("--offset requires a value");
        return 1;
      }
      config.offset_ns = ParseInt64OrDie(argv[i], "--offset");
    } else if (strcmp(argv[i], "--offset-ms") == 0) {
      if (++i >= argc) {
        PERFETTO_ELOG("--offset-ms requires a value");
        return 1;
      }
      config.offset_ns = ParseInt64OrDie(argv[i], "--offset-ms") * kNsPerMs;
    } else if (strcmp(argv[i], "--offset-s") == 0) {
      if (++i >= argc) {
        PERFETTO_ELOG("--offset-s requires a value");
        return 1;
      }
      config.offset_ns = ParseInt64OrDie(argv[i], "--offset-s") * kNsPerS;
    } else if (strcmp(argv[i], "--duration") == 0) {
      if (++i >= argc) {
        PERFETTO_ELOG("--duration requires a value");
        return 1;
      }
      config.duration_ns = ParseInt64OrDie(argv[i], "--duration");
    } else if (strcmp(argv[i], "--duration-ms") == 0) {
      if (++i >= argc) {
        PERFETTO_ELOG("--duration-ms requires a value");
        return 1;
      }
      config.duration_ns =
          ParseInt64OrDie(argv[i], "--duration-ms") * kNsPerMs;
    } else if (strcmp(argv[i], "--duration-s") == 0) {
      if (++i >= argc) {
        PERFETTO_ELOG("--duration-s requires a value");
        return 1;
      }
      config.duration_ns = ParseInt64OrDie(argv[i], "--duration-s") * kNsPerS;
    } else if (argv[i][0] == '-') {
      PERFETTO_ELOG("Unknown option: %s", argv[i]);
      PrintUsage(argv[0]);
      return 1;
    } else {
      // Positional argument
      if (input_file == nullptr) {
        input_file = argv[i];
      } else if (output_file == nullptr) {
        output_file = argv[i];
      } else {
        PERFETTO_ELOG("Too many arguments");
        PrintUsage(argv[0]);
        return 1;
      }
    }
  }

  if (input_file == nullptr || output_file == nullptr) {
    PERFETTO_ELOG("Missing input or output file");
    PrintUsage(argv[0]);
    return 1;
  }

  // Validate configuration
  if (config.offset_ns < 0) {
    PERFETTO_ELOG("Offset cannot be negative");
    return 1;
  }
  if (config.duration_ns < 0) {
    PERFETTO_ELOG("Duration cannot be negative");
    return 1;
  }

  PERFETTO_LOG("Extracting time segment from trace:");
  PERFETTO_LOG("  Input:    %s", input_file);
  PERFETTO_LOG("  Output:   %s", output_file);
  PERFETTO_LOG("  Offset:   %lld ns (%.3f s)",
               static_cast<long long>(config.offset_ns),
               static_cast<double>(config.offset_ns) / kNsPerS);
  if (config.duration_ns > 0) {
    PERFETTO_LOG("  Duration: %lld ns (%.3f s)",
                 static_cast<long long>(config.duration_ns),
                 static_cast<double>(config.duration_ns) / kNsPerS);
  } else {
    PERFETTO_LOG("  Duration: until end of trace");
  }

  auto extractor =
      perfetto::trace_redaction::TraceTimeExtractor::Create(config);

  perfetto::trace_redaction::Context context;
  auto status = extractor->Extract(input_file, output_file, &context);

  if (!status.ok()) {
    PERFETTO_ELOG("Extraction failed: %s", status.c_message());
    return 1;
  }

  const auto& final_config = extractor->config();
  PERFETTO_LOG("Extraction complete:");
  PERFETTO_LOG("  Trace time range: [%lld, %lld] ns",
               static_cast<long long>(final_config.trace_start_ns),
               static_cast<long long>(final_config.trace_end_ns));
  PERFETTO_LOG("  Extraction window: [%lld, %lld] ns",
               static_cast<long long>(final_config.extraction_start_ns),
               static_cast<long long>(final_config.extraction_end_ns));
  PERFETTO_LOG("  Extracted duration: %.3f s",
               static_cast<double>(final_config.extraction_end_ns -
                                   final_config.extraction_start_ns) /
                   kNsPerS);

  return 0;
}
