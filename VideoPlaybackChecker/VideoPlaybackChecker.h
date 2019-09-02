#pragma once

#include "Module.h"

#include <interfaces/IPlay.h>
#include <interfaces/json/JsonData_VideoPlaybackChecker.h>

namespace WPEFramework {
namespace Plugin {

    class VideoPlaybackChecker : public PluginHost::IPlugin, public PluginHost::JSONRPC {
    public:
        // maximum wait time for process to be spawned
        static constexpr uint32_t ImplWaitTime = 1000;

    public:
        VideoPlaybackChecker(const VideoPlaybackChecker&) = delete;
        VideoPlaybackChecker& operator=(const VideoPlaybackChecker&) = delete;

    private:
        class Notification : public RPC::IRemoteConnection::INotification {
        public:
            Notification() = delete;
            Notification(const Notification&) = delete;

        public:
            explicit Notification(VideoPlaybackChecker* parent)
                : _parent(*parent)
            {
                ASSERT(parent != nullptr);
            }
            virtual ~Notification() = default;

        public:
            virtual void Activated(RPC::IRemoteConnection* connection) { _parent.Activated(connection); }

            virtual void Deactivated(RPC::IRemoteConnection* connection) { _parent.Deactivated(connection); }

            BEGIN_INTERFACE_MAP(Notification)
            INTERFACE_ENTRY(RPC::IRemoteConnection::INotification)
            END_INTERFACE_MAP

        private:
            VideoPlaybackChecker& _parent;
        };

    public:
        VideoPlaybackChecker()
            : _service(nullptr)
            , _notification(this)
            , _VideoPlaybackCheckerImpl(nullptr)
            , _connectionId(0)
        {
            RegisterAll();
        }

        virtual ~VideoPlaybackChecker()
        {
            UnregisterAll();
        }

        BEGIN_INTERFACE_MAP(VideoPlaybackChecker)
        INTERFACE_ENTRY(PluginHost::IPlugin)
        INTERFACE_ENTRY(PluginHost::IDispatcher)
        INTERFACE_AGGREGATE(Exchange::IPlay, _VideoPlaybackCheckerImpl)
        END_INTERFACE_MAP

        //   IPlugin methods
        // -------------------------------------------------------------------------------------------------------
        virtual const string Initialize(PluginHost::IShell* service) override;
        virtual void Deinitialize(PluginHost::IShell* service) override;
        virtual string Information() const override;

    private:
        void Activated(RPC::IRemoteConnection* connection);
        void Deactivated(RPC::IRemoteConnection* connection);

        void ConnectionTermination(uint32_t connectionId);

        // JSON-RPC
        void RegisterAll();
        void UnregisterAll();
        uint32_t endpoint_play(const JsonData::VideoPlaybackChecker::PlayParamsData& params);

        PluginHost::IShell* _service;
        Core::Sink<Notification> _notification;
        Exchange::IPlay* _VideoPlaybackCheckerImpl;
        uint32_t _connectionId;
    };

} // namespace Plugin
} // namespace WPEFramework
