// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

/// @file util/spsc_queue.h
/// @brief Bounded lock-free queue for one producer and one consumer.

#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <optional>
#include <utility>

namespace wirepeek::util {

/// Fixed-capacity single-producer/single-consumer queue.
///
/// Exactly one thread may call TryPush/Emplace and exactly one other thread may
/// call TryPop. The queue does not allocate after construction.
template <typename T, size_t Capacity>
class SpscQueue {
  static_assert(Capacity > 0, "SpscQueue capacity must be positive");

 public:
  SpscQueue() = default;
  SpscQueue(const SpscQueue&) = delete;
  SpscQueue& operator=(const SpscQueue&) = delete;

  bool TryPush(const T& value) { return Emplace(value); }
  bool TryPush(T&& value) { return Emplace(std::move(value)); }

  template <typename... Args>
  bool Emplace(Args&&... args) {
    const size_t head = head_.load(std::memory_order_relaxed);
    const size_t next = Increment(head);
    if (next == tail_.load(std::memory_order_acquire)) {
      return false;
    }
    slots_[head].emplace(std::forward<Args>(args)...);
    head_.store(next, std::memory_order_release);
    return true;
  }

  std::optional<T> TryPop() {
    const size_t tail = tail_.load(std::memory_order_relaxed);
    if (tail == head_.load(std::memory_order_acquire)) {
      return std::nullopt;
    }
    std::optional<T> result(std::move(*slots_[tail]));
    slots_[tail].reset();
    tail_.store(Increment(tail), std::memory_order_release);
    return result;
  }

  [[nodiscard]] bool Empty() const noexcept {
    return tail_.load(std::memory_order_acquire) == head_.load(std::memory_order_acquire);
  }

  [[nodiscard]] size_t SizeApprox() const noexcept {
    const size_t head = head_.load(std::memory_order_acquire);
    const size_t tail = tail_.load(std::memory_order_acquire);
    return head >= tail ? head - tail : kStorageSize - tail + head;
  }

  [[nodiscard]] static constexpr size_t capacity() noexcept { return Capacity; }

 private:
  static constexpr size_t kStorageSize = Capacity + 1;
  static constexpr size_t Increment(size_t index) noexcept {
    return index + 1 == kStorageSize ? 0 : index + 1;
  }

  std::array<std::optional<T>, kStorageSize> slots_{};
  alignas(64) std::atomic<size_t> head_{0};
  alignas(64) std::atomic<size_t> tail_{0};
};

}  // namespace wirepeek::util
