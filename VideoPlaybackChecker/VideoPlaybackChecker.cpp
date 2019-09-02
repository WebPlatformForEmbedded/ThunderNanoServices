#include "VideoPlaybackChecker.h"

namespace WPEFramework {

namespace Plugin {
    SERVICE_REGISTRATION(VideoPlaybackChecker, 1, 0);

    /* virtual */ const string VideoPlaybackChecker::Initialize(PluginHost::IShell* service)
    {
        string message = EMPTY_STRING;

        ASSERT(service != nullptr);
        ASSERT(_service == nullptr);
        ASSERT(_VideoPlaybackCheckerImpl == nullptr);

        _service = service;
        _service->Register(&_notification);

        _VideoPlaybackCheckerImpl = _service->Root<Exchange::IPlay>(_connectionId, ImplWaitTime, _T("VideoPlaybackCheckerImpl"));

        if (_VideoPlaybackCheckerImpl == nullptr) {
            ConnectionTermination(_connectionId);
            _service->Unregister(&_notification);
            _service = nullptr;
            _VideoPlaybackCheckerImpl = nullptr;

            TRACE(Trace::Fatal, (_T("VideoPlaybackChecker could not be instantiated.")))
            message = _T("VideoPlaybackChecker could not be instantiated.");
        }

        return message;
    }

    /* virtual */ void VideoPlaybackChecker::Deinitialize(PluginHost::IShell* service)
    {
        ASSERT(_service == service);
        ASSERT(_VideoPlaybackCheckerImpl != nullptr);

        if (_VideoPlaybackCheckerImpl->Release() != Core::ERROR_DESTRUCTION_SUCCEEDED) {
            TRACE(Trace::Information, (_T("VideoPlaybackChecker is not properly destructed (connectionId=%d)"), _connectionId));
            ConnectionTermination(_connectionId);
        }

        _VideoPlaybackCheckerImpl = nullptr;
        _service->Unregister(&_notification);
        _service = nullptr;
    }

    /* virtual */ string VideoPlaybackChecker::Information() const
    {
        return ((_T("The purpose of this plugin is to test playback through the Secure Video Pipeline.")));
    }

    void VideoPlaybackChecker::ConnectionTermination(uint32_t connectionId)
    {
        RPC::IRemoteConnection* connection(_service->RemoteConnection(connectionId));
        if (connection != nullptr) {
            connection->Terminate();
            connection->Release();
        }
    }

    void VideoPlaybackChecker::Activated(RPC::IRemoteConnection* /*connection*/)
    {
        return;
    }

    void VideoPlaybackChecker::Deactivated(RPC::IRemoteConnection* connection)
    {
        if (_connectionId == connection->Id()) {
            ASSERT(_service != nullptr);
            PluginHost::WorkerPool::Instance().Submit(PluginHost::IShell::Job::Create(_service, PluginHost::IShell::DEACTIVATED, PluginHost::IShell::FAILURE));
        }
    }
} // namespace Plugin
} // namespace WPEFramework
