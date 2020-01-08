#pragma once

#include "Module.h"
#include "interfaces/IRemoteInvocation.h"

namespace WPEFramework {
namespace Plugin {

    class RemoteInvocation : public PluginHost::IPlugin {
    public:

        class Config : public Core::JSON::Container {
        private:
            Config(const Config&) = delete;
            Config& operator=(const Config&) = delete;

        public:
            Config()
                : Core::JSON::Container()
                , Address("0.0.0.0:5797")
            {
                Add(_T("address"), &Address);
            }

            ~Config()
            {
            }

        public:
            Core::JSON::String Address;
        };

        class Invocator : public Exchange::IRemoteInvocation {
        public:
            Invocator(const Invocator&) = delete;
            Invocator& operator=(const Invocator&) = delete;

            Invocator(const string& remoteId, PluginHost::IShell* service)
                : _remoteId(remoteId)
                , _service(service)
                , _refCount(1)
            {
            }

            void AddRef() const override {
                _refCount++;
            };
            uint32_t Release() const override {
                _refCount--;

                if (_refCount <= 0) {
                    delete this;
                    return Core::ERROR_DESTRUCTION_SUCCEEDED;
                }

                return Core::ERROR_NONE;
            };

            virtual ~Invocator()
            {
            }

            BEGIN_INTERFACE_MAP(Invocator)
            INTERFACE_ENTRY(Exchange::IRemoteInvocation)
            END_INTERFACE_MAP

            //   IRemoteInvocaiton methods
            // --------------------------------------------------------------------------------------------------------
            uint32_t LinkByCallsign(const uint16_t port, const uint32_t interfaceId, const uint32_t exchangeId, const string& callsign);
            uint32_t Unlink(const uint32_t exchangeId) override;
        private:
            string _remoteId;
            PluginHost::IShell* _service;
            mutable uint32_t _refCount;
        };


        class ExternalAccess : public RPC::Communicator {
        private:
            ExternalAccess() = delete;
            ExternalAccess(const ExternalAccess&) = delete;
            ExternalAccess& operator=(const ExternalAccess&) = delete;

        public:
            ExternalAccess(
                const Core::NodeId& source, 
                PluginHost::IShell* service,
                const Core::ProxyType<RPC::InvokeServer> & engine)
                : RPC::Communicator(source, _T(""), Core::ProxyType<Core::IIPCServer>(engine))
                , _service(service)
            {
                engine->Announcements(Announcement());
                Open(Core::infinite);
            }
            ~ExternalAccess()
            {
                Close(Core::infinite);
            }

        private:
            virtual void* Aquire(uint32_t id, const string& className, const uint32_t interfaceId, const uint32_t versionId)
            {
                void* result = nullptr;

                if (interfaceId == Exchange::IRemoteInvocation::ID) {
                    string source = Connection(id)->RemoteId();

                    TRACE(Trace::Information, ("Remote invocation instance requested from %s\n", source.c_str()));
                    result = new Invocator(source, _service);
                } else {
                    TRACE_L1("Failed to get interface %d from RemoteInvocation. Only %d is supported ", interfaceId, Exchange::IRemoteInvocation::ID)
                }

                return result;
            }

            PluginHost::IShell* _service;
        };

        RemoteInvocation(const RemoteInvocation&) = delete;
        RemoteInvocation& operator=(const RemoteInvocation&) = delete;

        RemoteInvocation()
        {
        }

        virtual ~RemoteInvocation()
        {

        }

        BEGIN_INTERFACE_MAP(RemoteInvocation)
            INTERFACE_ENTRY(PluginHost::IPlugin)
        END_INTERFACE_MAP

    public:
        //   IPlugin methods
        // -------------------------------------------------------------------------------------------------------
        virtual const string Initialize(PluginHost::IShell* service) override;
        virtual void Deinitialize(PluginHost::IShell* service) override;
        virtual string Information() const override;
    public:
        ExternalAccess* _extService;
    };

} // namespace Plugin
} // namespace WPEFramework