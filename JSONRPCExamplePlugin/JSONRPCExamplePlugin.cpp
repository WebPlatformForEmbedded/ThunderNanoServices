#include "JSONRPCExamplePlugin.h"

namespace WPEFramework {

namespace Plugin {

    SERVICE_REGISTRATION(JSONRPCExamplePlugin, 1, 0);

    JSONRPCExamplePlugin::JSONRPCExamplePlugin()
        : PluginHost::JSONRPC()
        , _job(Core::ProxyType<PeriodicSync>::Create(this))
    {
        // PluginHost::JSONRPC method to register a JSONRPC method invocation for the method "time".
        Register<Core::JSON::String, Core::JSON::String>(_T("time"), &JSONRPCExamplePlugin::time, this);
    }

    /* virtual */ JSONRPCExamplePlugin::~JSONRPCExamplePlugin()
    {
    }

    /* virtual */ const string JSONRPCExamplePlugin::Initialize(PluginHost::IShell* /* service */)
    {
        _job->Period(5);
        Core::IWorkerPool::Instance().Schedule(Core::Time::Now().Add(5000), _job);

        // On success return empty, to indicate there is no error text.
        return (string());
    }

    /* virtual */ void JSONRPCExamplePlugin::Deinitialize(PluginHost::IShell* /* service */)
    {
        _job->Period(0);
        Core::IWorkerPool::Instance().Revoke(_job);
    }

    /* virtual */ string JSONRPCExamplePlugin::Information() const
    {
        // No additional info to report.
        return (string());
    }

    void JSONRPCExamplePlugin::SendTime()
    {
        // PluginHost::JSONRPC method to send out a JSONRPC message to all subscribers to the event "clock".
        Notify(_T("clock"), Core::JSON::String(Core::Time::Now().ToRFC1123()));
    }

} // namespace Plugin

} // namespace WPEFramework
