#include "core/eventbus/EventBus.h"
#include "core/Logger.h"

EventBus &EventBus::instance()
{
    static EventBus inst;
    return inst;
}

EventBus::SubToken EventBus::subscribe(EventType type, std::function<void(const Event &)> callback)
{
    std::lock_guard<std::mutex> lk(mutex_);
    SubToken token = next_token_++;
    subscribers_[type].push_back({token, std::move(callback)});
    return token;
}

void EventBus::unsubscribe(SubToken token)
{
    std::lock_guard<std::mutex> lk(mutex_);
    for (auto &pair : subscribers_)
    {
        auto &list = pair.second;
        auto it = list.begin();
        while (it != list.end())
        {
            if (it->token == token)
            {
                it = list.erase(it);
            }
            else
            {
                ++it;
            }
        }
    }
}

void EventBus::publish(Event event)
{
    // Copy the subscriber list under the lock, then dispatch outside it.
    // This prevents re-entrancy deadlocks when a callback itself publishes.
    std::vector<std::function<void(const Event &)>> callbacks;
    {
        std::lock_guard<std::mutex> lk(mutex_);
        auto it = subscribers_.find(event.type);
        if (it != subscribers_.end())
        {
            for (const auto &sub : it->second)
            {
                callbacks.push_back(sub.callback);
            }
        }
    }

    Logger::instance().log(LogLevel::DEBUG, "EVENTBUS",
                           "event published type=" + std::to_string(static_cast<int>(event.type)));

    for (auto &cb : callbacks)
    {
        cb(event);
    }
}