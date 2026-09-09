// Copyright 2026 lucientong
// SPDX-License-Identifier: Apache-2.0

#include <wirepeek/util/spsc_queue.h>

#include <atomic>
#include <gtest/gtest.h>
#include <memory>
#include <thread>
#include <vector>

namespace wirepeek::util {
namespace {

TEST(SpscQueueTest, PreservesFifoAndReportsFull) {
  SpscQueue<int, 3> queue;
  EXPECT_TRUE(queue.Empty());
  EXPECT_TRUE(queue.TryPush(1));
  EXPECT_TRUE(queue.TryPush(2));
  EXPECT_TRUE(queue.TryPush(3));
  EXPECT_FALSE(queue.TryPush(4));
  EXPECT_EQ(queue.SizeApprox(), 3u);

  EXPECT_EQ(queue.TryPop(), 1);
  EXPECT_EQ(queue.TryPop(), 2);
  EXPECT_TRUE(queue.TryPush(4));
  EXPECT_EQ(queue.TryPop(), 3);
  EXPECT_EQ(queue.TryPop(), 4);
  EXPECT_FALSE(queue.TryPop().has_value());
}

TEST(SpscQueueTest, SupportsMoveOnlyValues) {
  SpscQueue<std::unique_ptr<int>, 1> queue;
  ASSERT_TRUE(queue.TryPush(std::make_unique<int>(42)));
  auto value = queue.TryPop();
  ASSERT_TRUE(value.has_value());
  EXPECT_EQ(**value, 42);
}

TEST(SpscQueueTest, TransfersBetweenTwoThreads) {
  constexpr int kCount = 10000;
  SpscQueue<int, 128> queue;
  std::vector<int> received;
  received.reserve(kCount);
  std::atomic<bool> start{false};

  std::thread producer([&] {
    while (!start.load(std::memory_order_acquire)) {
    }
    for (int value = 0; value < kCount; ++value) {
      while (!queue.TryPush(value)) {
      }
    }
  });
  std::thread consumer([&] {
    start.store(true, std::memory_order_release);
    while (received.size() < kCount) {
      if (auto value = queue.TryPop()) {
        received.push_back(*value);
      }
    }
  });

  producer.join();
  consumer.join();
  ASSERT_EQ(received.size(), static_cast<size_t>(kCount));
  for (int i = 0; i < kCount; ++i) {
    EXPECT_EQ(received[static_cast<size_t>(i)], i);
  }
}

}  // namespace
}  // namespace wirepeek::util
