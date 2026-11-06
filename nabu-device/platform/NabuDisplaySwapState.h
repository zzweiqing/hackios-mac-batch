#pragma once
#include <stdint.h>

class NabuDisplayQueuePump {
    unsigned depth_ = 0;
    bool requested_ = false;
public:
    class Pause {
        NabuDisplayQueuePump &pump_;
    public:
        explicit Pause(NabuDisplayQueuePump &pump) : pump_(pump) { ++pump_.depth_; }
        ~Pause() { --pump_.depth_; }
        Pause(const Pause &) = delete;
        Pause &operator=(const Pause &) = delete;
    };

    void request() { requested_ = true; }

    template <class Step> void drain(Step step) {
        request();
        if (depth_) return;
        Pause pause(*this);
        while (requested_) {
            requested_ = false;
            step();
        }
    }
};

class NabuGpuFrameState {
public:
    enum class Phase : uint8_t { Empty, Offered, Delivered, CompletionUnknown };
private:
    Phase phase_ = Phase::Empty;
public:
    bool empty() const { return phase_ == Phase::Empty; }
    bool offered() const { return phase_ == Phase::Offered; }
    bool delivered() const { return phase_ == Phase::Delivered; }
    bool inFlight() const { return !empty(); }
    void offer() { phase_ = Phase::Offered; }
    void deliver() { phase_ = Phase::Delivered; }
    void complete() { phase_ = Phase::Empty; }
    void quarantine() { phase_ = Phase::CompletionUnknown; }
};
