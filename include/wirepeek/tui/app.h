// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

/// @file tui/app.h
/// @brief Main TUI application using FTXUI.

#pragma once

#include <wirepeek/capture/capture.h>
#include <wirepeek/tui/ui_state.h>

#include <atomic>
#include <memory>
#include <string>

namespace wirepeek::tui {

/// TUI application configuration.
struct TuiConfig {
  bool no_reassemble = false;
};

/// Main TUI application.
///
/// Runs the FTXUI event loop on the main thread and captures packets
/// on a background thread. Data flows through a thread-safe UiState.
class TuiApp {
 public:
  explicit TuiApp(TuiConfig config = {});
  ~TuiApp();

  /// Run the TUI with the given capture source. Blocks until user quits.
  void Run(std::unique_ptr<capture::CaptureSource> source);

 private:
  /// Background capture thread function.
  void CaptureLoop(capture::CaptureSource& source);

  TuiConfig config_;
  std::shared_ptr<UiState> state_;
  std::atomic<bool> running_{false};
};

}  // namespace wirepeek::tui
