#pragma once
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace capslang::profile_channel {
// Exactly one producer and one consumer. Used between the host UI thread and
// its local IPC worker, never across processes. No allocation, locks or waits
// in a TSF notification. Full means lost delivery unless the caller retains the
// item; it must NOT be silently ignored or reported as synchronized.
template<class T, std::size_t Capacity> class Queue {
    static_assert(Capacity > 0 && std::is_trivially_copyable_v<T>);
    static_assert(std::atomic<std::uint64_t>::is_always_lock_free,
                  "UI producer must not acquire a hidden runtime lock");
public:
    bool TryPush(const T& value) noexcept {
        const auto write = write_.load(std::memory_order_relaxed);
        const auto read = read_.load(std::memory_order_acquire);
        if (write == UINT64_MAX || read > write || write - read >= Capacity) return false;
        values_[write % Capacity] = value;
        write_.store(write + 1, std::memory_order_release);
        return true;
    }
    bool TryPop(T& value) noexcept {
        const auto read = read_.load(std::memory_order_relaxed);
        if (read == write_.load(std::memory_order_acquire)) return false;
        value = values_[read % Capacity];
        read_.store(read + 1, std::memory_order_release);
        return true;
    }
private:
    std::array<T, Capacity> values_{};
    alignas(64) std::atomic<std::uint64_t> write_{0};
    alignas(64) std::atomic<std::uint64_t> read_{0};
};
} // namespace capslang::profile_channel
