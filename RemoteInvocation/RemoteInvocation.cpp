#include "RemoteInvocation.h"
#include "plugins/IShell.h"
#include "protocols/IRemoteLinker.h"

namespace WPEFramework {
namespace Plugin {

    SERVICE_REGISTRATION(RemoteInvocation, 1, 0);

    static std::map<uint32_t, Core::IUnknown*> connectionMap;

    const string RemoteInvocation::Initialize(PluginHost::IShell* service) 
    {
        Config config;
        config.FromString(service->ConfigLine());

        Core::NodeId serverAddress(config.Address.Value().c_str());

        Core::ProxyType<RPC::InvokeServer> server = Core::ProxyType<RPC::InvokeServer>::Create(&Core::WorkerPool::Instance());
        _extService = new ExternalAccess(serverAddress, service, server);

        return (string());
    }

    void RemoteInvocation::Deinitialize(PluginHost::IShell* service) 
    {   
        if (_extService != nullptr) {
            delete _extService;
            _extService = nullptr;
        }
    }

    string RemoteInvocation::Information() const 
    {
        return (string());
    }

    uint32_t RemoteInvocation::Invocator::LinkByCallsign(const uint16_t port, const uint32_t interfaceId, const uint32_t exchangeId, const string& callsign) 
    {
        uint32_t result = Core::ERROR_NONE;
        string remoteAddress = Core::NodeId(_remoteId.c_str()).HostAddress() + ":" + std::to_string(port);

        auto plugin = reinterpret_cast<Core::IUnknown*>(_service->QueryInterfaceByCallsign(RPC::IRemoteLinker::ID, callsign));

        if (plugin != nullptr) {
            auto linker = plugin->QueryInterface<RPC::IRemoteLinker>();

            if (linker != nullptr) {
                result = linker->Link(remoteAddress, interfaceId, exchangeId);
                linker->Release();

                connectionMap.insert(std::pair<uint32_t, Core::IUnknown*>(exchangeId, plugin));
                plugin->AddRef();
            } else {
                result = Core::ERROR_ILLEGAL_STATE;
            }

            plugin->Release();
        } else {
            result = Core::ERROR_UNAVAILABLE;
        }

        return result;
    }

    uint32_t RemoteInvocation::Invocator::Unlink(const uint32_t exchangeId) 
    {
        uint32_t result = Core::ERROR_NONE;
        auto plugin = connectionMap.find(exchangeId);

        if (plugin != connectionMap.end()) {
            auto linker = plugin->second->QueryInterface<RPC::IRemoteLinker>();

            if (linker != nullptr) {
                result = linker->Unlink();

                if (result == Core::ERROR_NONE) {
                    plugin->second->Release();
                    connectionMap.erase(exchangeId);
                }
            } else {
                result = Core::ERROR_ILLEGAL_STATE;
            }
        }
    }
}
}