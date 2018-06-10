#include <stdio.h>
#include <string.h>
#include "Module.h"

#include <interfaces/IComposition.h>

#include <IPlatform.h>


MODULE_NAME_DECLARATION(BUILD_REFERENCE)

namespace WPEFramework {
namespace Plugin {
    /* -------------------------------------------------------------------------------------------------------------
     * This is a singleton. Declare all C accessors to this object here
     * ------------------------------------------------------------------------------------------------------------- */
    class CompositorImplementation;

    static CompositorImplementation* g_implementation = nullptr;
    static Core::CriticalSection g_implementationLock;

    /* -------------------------------------------------------------------------------------------------------------
     *
     * ------------------------------------------------------------------------------------------------------------- */
    class CompositorImplementation : public Exchange::IComposition {
    private:
        const std::map<const Exchange::IComposition::ScreenResolution, const NEXUS_VideoFormat > formatLookup = {
                { Exchange::IComposition::ScreenResolution::ScreenResolution_Unknown, NEXUS_VideoFormat_eUnknown },
                { Exchange::IComposition::ScreenResolution::ScreenResolution_480i, NEXUS_VideoFormat_eNtsc },
                { Exchange::IComposition::ScreenResolution::ScreenResolution_480p, NEXUS_VideoFormat_e480p },
                { Exchange::IComposition::ScreenResolution::ScreenResolution_720p, NEXUS_VideoFormat_e720p },
                { Exchange::IComposition::ScreenResolution::ScreenResolution_720p50Hz, NEXUS_VideoFormat_e720p50hz },
                { Exchange::IComposition::ScreenResolution::ScreenResolution_1080p24Hz, NEXUS_VideoFormat_e1080p24hz },
                { Exchange::IComposition::ScreenResolution::ScreenResolution_1080i50Hz, NEXUS_VideoFormat_e1080i50hz },
                { Exchange::IComposition::ScreenResolution::ScreenResolution_1080p50Hz, NEXUS_VideoFormat_e1080p50hz },
                { Exchange::IComposition::ScreenResolution::ScreenResolution_1080p60Hz, NEXUS_VideoFormat_e1080p60hz }
        };

    private:
        CompositorImplementation(const CompositorImplementation&) = delete;
        CompositorImplementation& operator=(const CompositorImplementation&) = delete;

    private:
        class Entry : public Exchange::IComposition::IClient {
        private:
            Entry() = delete;
            Entry(const Entry&) = delete;
            Entry& operator=(const Entry&) = delete;

        protected:
            Entry(nxclient_t client, const NxClient_JoinSettings* settings)
                : _client(client)
                , _settings(*settings)
            {
                TRACE_L1("Created client named: %s", _settings.name);
            }

        public:
            static Entry* Create(nxclient_t client, const NxClient_JoinSettings* settings)
            {
                Entry* result = Core::Service<Entry>::Create<Entry>(client, settings);

                return (result);
            }
            virtual ~Entry()
            {
                TRACE_L1("Destructing client named: %s", _settings.name);
            }

        public:
            inline bool IsActive() const
            {
                return (_client != nullptr);
            }
            inline const char* Id() const
            {
                ASSERT(_client != nullptr);

                return (_settings.name);
            }
            virtual string Name() const override
            {
                return (string(Id()));
            }
            virtual void Kill() override
            {
                ASSERT(_client != nullptr);

                /* must call nxserver_ipc so it can unwind first. */
                nxserver_ipc_close_client(_client);

                TRACE(Trace::Information, (_T("Kill client %s."), Name().c_str()));

                /* We expect the Disconnect Client to be triggered by the previous call
                   TODO: Double check this is true, and if not call it explicitly here. */
            }
            virtual void Opacity(const uint32_t value) override
            {
                ASSERT(_client != nullptr);

                TRACE(Trace::Information, (_T("Alpha client %s to %d."), Name().c_str(), value));
                nxserverlib_set_server_alpha(_client, value);
            }

            virtual void Geometry(const uint32_t X, const uint32_t Y, const uint32_t width, const uint32_t height) override
            {
                // TODO
            }

            virtual void Visible(const bool visible) override
            {
                // TODO
            }

            virtual void SetTop()
            {
                ASSERT(_client != nullptr);

                /* the definition of "focus" is variable. this is one impl. */
                NxClient_ConnectList list;
                struct nxclient_status status;

                nxclient_get_status(_client, &status);
                NxClient_P_Config_GetConnectList(_client, status.handle, &list);

                /* only refresh first connect */
                if (list.connectId[0]) {
                    NxClient_P_RefreshConnect(_client, list.connectId[0]);
                }

                TRACE(Trace::Information, (_T("Focus client %s."), Name().c_str()));

                nxserver_p_focus_surface_client(_client);
            }

            virtual void SetInput()
            {
                // TODO
            }

            BEGIN_INTERFACE_MAP(Entry)
            INTERFACE_ENTRY(Exchange::IComposition::IClient)
            END_INTERFACE_MAP

        private:
            nxclient_t _client;
            NxClient_JoinSettings _settings;
        };

    public:
        CompositorImplementation()
            : _instance(nullptr)
            , _joinSettings()
            , _compositionClients()
            , _clients()
            , _service()
            , _sink(this)
            , _nxserver(nullptr)
        {
            // Register an @Exit, in case we are killed, with an incorrect ref count !!
            if (atexit(CloseDown) != 0) {
                TRACE(Trace::Information, (("Could not register @exit handler. Error: %d."), errno));
                exit(EXIT_FAILURE);
            }

            // Nexus can only be instantiated once (it is a process wide singleton !!!!)
            ASSERT(g_implementation == nullptr);

            g_implementation = this;

            _nxserver = Exchange::IPlatform::Instance();
        }

        ~CompositorImplementation()
        {
            NxClient_Uninit();
            BSTD_UNUSED(_instance);

            if (_service != nullptr) {
                _service->Release();
            }
        }

    public:
        BEGIN_INTERFACE_MAP(CompositorImplementation)
        INTERFACE_ENTRY(Exchange::IComposition)
        END_INTERFACE_MAP

    public:
        // -------------------------------------------------------------------------------------------------------
        //   IComposition methods
        // -------------------------------------------------------------------------------------------------------
        /* virtual */ uint32_t Configure(PluginHost::IShell* service)
        {
            _service = service;
            _service->AddRef();

            ASSERT(_nxserver != nullptr);

            // No config yet but we could poke in the join settings here...
            // _config.FromString(_service->ConfigLine());

            if (_nxserver != nullptr) {
                _nxserver->Callback(&_sink);

                _nxserver->Configure(_service);
            }

            return  Core::ERROR_NONE;
        }

        /* virtual */ void Register(Exchange::IComposition::INotification* notification)
        {
            // Do not double register a notification sink.
            g_implementationLock.Lock();
            ASSERT(std::find(_compositionClients.begin(), _compositionClients.end(), notification) == _compositionClients.end());

            notification->AddRef();

            _compositionClients.push_back(notification);

            std::list<Entry*>::iterator index(_clients.begin());

            while (index != _clients.end()) {

                if ((*index)->IsActive() == true) {
                    notification->Attached(*index);
                }
                index++;
            }

            g_implementationLock.Unlock();
        }

        /* virtual */ void Unregister(Exchange::IComposition::INotification* notification)
        {
            g_implementationLock.Lock();

            std::list<Exchange::IComposition::INotification*>::iterator index(std::find(_compositionClients.begin(), _compositionClients.end(), notification));

            // Do not un-register something you did not register.
            ASSERT(index != _compositionClients.end());

            if (index != _compositionClients.end()) {

                _compositionClients.erase(index);

                notification->Release();
            }

            g_implementationLock.Unlock();
        }

        /* virtual */ Exchange::IComposition::IClient* Client(const uint8_t id)
        {
            uint8_t count = id;
            Exchange::IComposition::IClient* result = nullptr;

            g_implementationLock.Lock();

            std::list<Entry*>::iterator index(_clients.begin());

            while ((count != 0) && (index != _clients.end())) {
                if ((*index)->IsActive() == true)
                    count--;
                index++;
            }

            if (index != _clients.end()) {
                result = (*index);
                result->AddRef();
            }

            g_implementationLock.Unlock();

            return (result);
        }

        /* virtual */ Exchange::IComposition::IClient* Client(const string& name)
        {
            Exchange::IComposition::IClient* result = nullptr;

            g_implementationLock.Lock();

            std::list<Entry*>::iterator index(_clients.begin());

            while ((index != _clients.end()) && ((*index)->Name() != name)) {
                index++;
            }

            if ((index != _clients.end()) && ((*index)->IsActive() == true)) {
                result = (*index);
                result->AddRef();
            }

            g_implementationLock.Unlock();

            return (result);
        }
        /* virtual */ void SetResolution(const Exchange::IComposition::ScreenResolution format)
        {

            NEXUS_Error rc;
            NxClient_DisplaySettings displaySettings;

            NxClient_GetDisplaySettings(&displaySettings);

            const auto index(formatLookup.find(format));

            if (index == formatLookup.cend() || index->second == NEXUS_VideoFormat_eUnknown
                || index->second == displaySettings.format) {

                TRACE(Trace::Information, (_T("Output resolution is already %d"), format));
                return;
            }

            if (displaySettings.format != index->second) {

                displaySettings.format = index->second;
                rc = NxClient_SetDisplaySettings(&displaySettings);
                if (rc) {

                    TRACE(Trace::Information, (_T("Setting resolution is failed: %d"), index->second));
                    return;
                }
            }
            TRACE(Trace::Information, (_T("New resolution is %d "), index->second));
            return;
        }
        /* virtual */ const ScreenResolution GetResolution()
        {
            NEXUS_Error rc;
            NxClient_DisplaySettings displaySettings;
            NEXUS_VideoFormat format;

            NxClient_GetDisplaySettings(&displaySettings);
            format = displaySettings.format;

            const auto index = std::find_if(formatLookup.cbegin(), formatLookup.cend(),
                      [format](const std::pair<const Exchange::IComposition::ScreenResolution, const NEXUS_VideoFormat>& found)
                      { return found.second == format; });

            if (index != formatLookup.cend()) {
                TRACE(Trace::Information, (_T("Resolution is %d "), index->second));
                return index->first;
            }
            else {
                TRACE(Trace::Information, (_T("Resolution is unknown")));
                return Exchange::IComposition::ScreenResolution::ScreenResolution_Unknown;
            }
        }
    private:
        void JoinServer(){
            TRACE(Trace::Information, (_T("Joining external NXServer.")));

            NEXUS_Error rc = NxClient_Join(&_joinSettings);

            if (rc == NEXUS_SUCCESS) {
                _instance = nxserverlib_get_singleton();

                ASSERT(_instance != nullptr);
            }
        }

        void Add(nxclient_t client, const NxClient_JoinSettings* joinSettings)
        {
            const std::string name(joinSettings->name);

            if (name.empty() == true) {
                TRACE(Trace::Information, (_T("Registration of a nameless client.")));
            }
            else {
                std::list<Entry*>::iterator index(_clients.begin());

                while ((index != _clients.end()) && (name != (*index)->Name())) {
                    index++;
                }

                if (index == _clients.end()) {
                    Entry* entry(Entry::Create(client, joinSettings));

                    _clients.push_back(entry);

                    TRACE(Trace::Information, (_T("Added client %s."), name.c_str()));

                    if (_compositionClients.size() > 0) {

                        std::list<Exchange::IComposition::INotification*>::iterator index(_compositionClients.begin());

                        while (index != _compositionClients.end()) {
                            (*index)->Attached(entry);
                            index++;
                        }
                    }
                }
                else {
                    TRACE(Trace::Information, (_T("Client already registered %s."), name.c_str()));
                }
            }
        }

        void Remove(const char clientName[])
        {
            const std::string name(clientName);

            if (name.empty() == true) {
                TRACE(Trace::Information, (_T("Registration of a nameless client.")));
            }
            else {
                std::list<Entry*>::iterator index(_clients.begin());

                while ((index != _clients.end()) && (name != (*index)->Name())) {
                    index++;
                }

                if (index != _clients.end()) {
                    Entry* entry(*index);

                    _clients.erase(index);

                    TRACE(Trace::Information, (_T("Removed client %s."), name.c_str()));

                    if (_compositionClients.size() > 0) {
                        std::list<Exchange::IComposition::INotification*>::iterator index(_compositionClients.begin());

                        while (index != _compositionClients.end()) {
                            (*index)->Detached(entry);
                            index++;
                        }
                    }

                    entry->Release();
                }
                else {
                    TRACE(Trace::Information, (_T("Client already unregistered %s."), name.c_str()));
                }
            }
        }

        PluginHost::ISubSystem* SubSystems()
        {
            return _service->SubSystems();
        }

        class Sink : public WPEFramework::Exchange::IPlatform::ICallback {
        private:
            Sink() = delete;
            Sink(const Sink&) = delete;
            Sink& operator=(const Sink&) = delete;

        public:
            explicit Sink(CompositorImplementation* parent)
                : _parent(*parent)
            {
                ASSERT(parent != nullptr);
            }
            ~Sink()
            {
            }

        public:
            // -------------------------------------------------------------------------------------------------------
            //   Exchange::IPlatform::ICallback methods
            // -------------------------------------------------------------------------------------------------------
            /* virtual */ void Attached(nxclient_t client, const NxClient_JoinSettings* joinSettings)
            {
                _parent.Add(client, joinSettings);

            }

            /* virtual */ void Detached(const char clientName[])
            {
                _parent.Remove(clientName);
            }

            /* virtual */ virtual void StateChange(Exchange::IPlatform::server_state state)
            {
                if(state == Exchange::IPlatform::OPERATIONAL){
                    _parent.JoinServer();

                    PluginHost::ISubSystem* subSystems = _parent.SubSystems();

                    ASSERT(subSystems != nullptr);

                    if (subSystems != nullptr) {
                        // Set Graphics event. We need to set up a handler for this at a later moment
                        subSystems->Set(PluginHost::ISubSystem::GRAPHICS, nullptr);
                        subSystems->Release();
                    }
                }
            }
        private:
            CompositorImplementation& _parent;
        };

        static void CloseDown()
        {
            // Make sure we get exclusive access to the Destruction of this Resource Center.
            g_implementationLock.Lock();

            // Seems we are destructed.....If we still have a pointer to the implementation, Kill it..
            if (g_implementation != nullptr) {
                delete g_implementation;
                g_implementation = nullptr;
            }
            g_implementationLock.Unlock();
        }

    private:
        nxserver_t _instance;
        NxClient_JoinSettings _joinSettings;
        std::list<Exchange::IComposition::INotification*> _compositionClients;
        std::list<Entry*> _clients;
        PluginHost::IShell* _service;
        Sink _sink;
        Exchange::IPlatform* _nxserver;
    };

    SERVICE_REGISTRATION(CompositorImplementation, 1, 0);

} // namespace Plugin
} // namespace WPEFramework
