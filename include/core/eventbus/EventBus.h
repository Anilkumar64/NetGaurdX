#pragma once
#include <unordered_map>
#include <vector>
#include <functional>
#include <mutex>
#include <string>
#include <any>
#include <cstdint>

// ── All event types the system can publish ────────────────────────────────

enum class EventType
{
    PACKET_CAPTURED,
    FLOW_CREATED,
    FLOW_UPDATED,
    FLOW_CLOSED,
    ALERT_DNS_FAILURE,
    ALERT_PACKET_LOSS,
    ALERT_HIGH_RETRANSMISSION,
    ALERT_TCP_RESET,
    METRICS_UPDATED,
    HEALING_ACTION,
    CAPTURE_STARTED,
    CAPTURE_STOPPED,
    INTERFACE_CHANGED
};

// ── Generic event payload ─────────────────────────────────────────────────

struct Event
{
    EventType type;
    double timestamp{0.0};
    std::string description;
    std::string layer;
    std::string severity;
    std::any payload; // type-erased; cast matches EventType
};

// ── Thread-safe publish/subscribe bus ────────────────────────────────────

class EventBus
{
public:
    using SubToken = uint64_t;

    static EventBus &instance();

    /// Register a callback for a specific event type.
    SubToken subscribe(EventType type, std::function<void(const Event &)> callback);

    /// Unregister a callback using the token returned by subscribe.
    void unsubscribe(SubToken token);

    /// Deliver an event to all registered subscribers.
    /// Dispatches OUTSIDE the internal lock to avoid re-entrancy deadlocks.
    void publish(Event event);

private:
    EventBus() = default;

    struct Subscriber {
        SubToken token;
        std::function<void(const Event &)> callback;
    };

    std::unordered_map<EventType, std::vector<Subscriber>> subscribers_;
    std::mutex mutex_;
    uint64_t next_token_{1};
};
