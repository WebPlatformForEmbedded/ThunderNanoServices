#include "Module.h"
#include "IPlatform.h"

#include <nexus_config.h>
#include <nexus_types.h>
#include <nexus_platform.h>
#include <nxclient.h>
#include <nxserverlib.h>
#include <nexus_display_vbi.h>
#include <nexus_otpmsp.h>
#include <nexus_read_otp_id.h>
/* print_capabilities */
#if NEXUS_HAS_VIDEO_DECODER
#include <nexus_video_decoder.h>
#endif
#include <nexus_display.h>

BDBG_MODULE(WPEFrameWorkNXServer);

namespace WPEFramework {
namespace Broadcom {
    class PlatformImplementation;

    static PlatformImplementation* g_instance = nullptr;
    static Core::CriticalSection g_lock;

    class PlatformImplementation : public Exchange::IPlatform {
    public:
        ~PlatformImplementation()
        {
            _state = Exchange::IPlatform::DEINITIALIZING;

            nxserver_ipc_uninit();
            nxserverlib_uninit(_instance);
            BKNI_DestroyMutex(_lock);
            NEXUS_Platform_Uninit();

            if (_service != nullptr) {
                _service->Release();
            }
        }

        PlatformImplementation()
                : _lock()
                , _instance()
                , _serverSettings()
                , _platformSettings()
                , _platformCapabilities()
                , _joinSettings()
                , _job(*this)
                , _state(Exchange::IPlatform::UNITIALIZED)
                , _service()
                , _nexusClients()
                , _clientHandler(nullptr)
        {
            // Register an @Exit, in case we are killed, with an incorrect ref count !!
            if (atexit(CloseDown) != 0) {
                TRACE(Trace::Information, (("Could not register @exit handler. Error: %d."), errno));
                exit(EXIT_FAILURE);
            }

            // make sure we have one nexus server in the system
            ASSERT(g_instance == nullptr);

            g_instance = this;
        }

    private:
        class Entry {
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
            static Entry* Create(nxclient_t client, const NxClient_JoinSettings& settings)
            {
                // Entry* result = Core::Service<Entry>::Create<Entry>(client, &settings);

                Entry* result = new Entry(client, &settings);
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
            string Name() const
            {
                return (string(Id()));
            }

        private:
            nxclient_t _client;
            NxClient_JoinSettings _settings;
        };

        class Job : public Core::Thread {
        private:
            Job() = delete;
            Job(const Job&) = delete;
            Job& operator=(const Job&) = delete;

        public:
            Job(PlatformImplementation& parent)
                : Core::Thread(64 * 1204, _T("PlatformInitialization"))
                , _parent(parent)
                , _sleeptime(0)

            {
            }
            virtual ~Job()
            {
            }

        public:
            void Initialize(const uint32_t sleepTime)
            {
                _sleeptime = sleepTime;

                Core::Thread::Run();
            }

        private:
            virtual uint32_t Worker()
            {
                Block();

                SleepMs(_sleeptime);

                _parent.PlatformReady();

                return Core::infinite;
            }

        private:
            PlatformImplementation& _parent;
            uint32_t _sleeptime;
        };
    public:
        class Config : public Core::JSON::Container {
        public:
            Config(const Config&);
            Config& operator=(const Config&);

        public:
            Config()
                : Core::JSON::Container()
                , HWDelay()
                , IRMode(NEXUS_IrInputMode_eCirNec)
                , Authentication(true)
                , BoxMode(1)
                , GraphicsHeap(0)
            {
                Add(_T("hardwareready"), &HWDelay);
                Add(_T("irmode"), &IRMode);
                Add(_T("authentication"), &Authentication);
                Add(_T("boxmode"), &BoxMode);
                Add(_T("graphicsheap"), &GraphicsHeap);
            }
            ~Config()
            {
            }

        public:
            Core::JSON::DecUInt16 HWDelay;
            Core::JSON::DecUInt16 IRMode;
            Core::JSON::Boolean Authentication;
            Core::JSON::DecUInt16 BoxMode;
            Core::JSON::DecUInt32 GraphicsHeap;
        };

        static PlatformImplementation* Create()
        {
            return g_instance == nullptr ? new PlatformImplementation() : g_instance;
        }

        // -------------------------------------------------------------------------------------------------------
        //   IPlatform methods
        // -------------------------------------------------------------------------------------------------------
        virtual void Callback(ICallback* callback) const
        {
            g_lock.Lock();
            assert((callback != nullptr) ^ (_clientHandler != nullptr));
            _clientHandler = callback;
            g_lock.Unlock();

            _clientHandler->StateChange(_state);
        }
        virtual uint32_t Configure(PluginHost::IShell* service) override
        {
            _service = service;
            _service->AddRef();

            uint32_t result = Core::ERROR_ILLEGAL_STATE;
            NEXUS_Error rc;
            Config config;
            config.FromString(_service->ConfigLine());

            ASSERT(_instance == nullptr);

            // Strange someone already started a NXServer.
            if (_instance == nullptr) {
                NxClient_GetDefaultJoinSettings(&(_joinSettings));
                strcpy(_joinSettings.name, "PlatformPlugin");

                nxserver_get_default_settings(&(_serverSettings));
                NEXUS_Platform_GetDefaultSettings(&(_platformSettings));
                NEXUS_GetDefaultMemoryConfigurationSettings(&(_serverSettings.memConfigSettings));
                NEXUS_GetPlatformCapabilities(&(_platformCapabilities));

                if (config.BoxMode.IsSet()) {
                    // Set box mode using env var.
                    std::stringstream boxMode;
                    boxMode << config.BoxMode.Value();
                    Core::SystemInfo::SetEnvironment(_T("B_REFSW_BOXMODE"), boxMode.str());
                }
                if (config.GraphicsHeap.IsSet() && config.GraphicsHeap.Value() > 0) {
                    TRACE(Trace::Information, (_T("PID[%d] Set graphics heap to %dMB\n"), getpid(), config.GraphicsHeap.Value()));
                    _platformSettings.heap[NEXUS_MEMC0_GRAPHICS_HEAP].size = config.GraphicsHeap.Value() * 1024 * 1024;
                }

                /* display[1] will always be either SD or transcode */
                if (!_platformCapabilities.display[1].supported || _platformCapabilities.display[1].encoder) {
                    for (unsigned int i = 0; i < NXCLIENT_MAX_SESSIONS; i++)
                        _serverSettings.session[i].output.sd = false;
                }
                /* display[0] will always be either HD, or system is headless */
                if (!_platformCapabilities.display[0].supported || _platformCapabilities.display[0].encoder) {
                    for (unsigned int i = 0; i < NXCLIENT_MAX_SESSIONS; i++)
                        _serverSettings.session[i].output.hd = false;
                }

#if NEXUS_HAS_IR_INPUT
                for (unsigned int i = 0; i < NXCLIENT_MAX_SESSIONS; i++)
#if NEXUS_PLATFORM_VERSION_MAJOR < 16 || (NEXUS_PLATFORM_VERSION_MAJOR == 16 && NEXUS_PLATFORM_VERSION_MINOR < 3)
                    _serverSettings.session[i].ir_input_mode = static_cast<NEXUS_IrInputMode>(config.IRMode.Value());
#else
                    for (unsigned int irInputIndex = 0; i < NXSERVER_IR_INPUTS; i++)
                        _serverSettings.session[i].ir_input.mode[irInputIndex] = static_cast<NEXUS_IrInputMode>(config.IRMode.Value());
#endif // NEXUS_PLATFORM_VERSION_MAJOR < 17
#endif // NEXUS_HAS_IR_INPUT

                struct nxserver_cmdline_settings cmdline_settings;
                memset(&cmdline_settings, 0, sizeof(cmdline_settings));
                cmdline_settings.frontend = true;
                cmdline_settings.loudnessMode = NEXUS_AudioLoudnessEquivalenceMode_eNone;
                _serverSettings.session[0].dolbyMs = nxserverlib_dolby_ms_type_none;

                rc = nxserver_modify_platform_settings(&_serverSettings,
                    &cmdline_settings,
                    &_platformSettings,
                    &_serverSettings.memConfigSettings);
                if (rc != NEXUS_SUCCESS) {
                    result = Core::ERROR_INCOMPLETE_CONFIG;
                }
                else {
                    rc = NEXUS_Platform_MemConfigInit(&_platformSettings, &_serverSettings.memConfigSettings);

                    if (rc != NEXUS_SUCCESS) {
                        result = Core::ERROR_UNKNOWN_KEY;
                    }
                    else {
                        BKNI_CreateMutex(&_lock);
                        _serverSettings.lock = _lock;

                        nxserver_set_client_heaps(&_serverSettings, &_platformSettings);

                        _serverSettings.client.connect = PlatformImplementation::ClientConnect;
                        _serverSettings.client.disconnect = PlatformImplementation::ClientDisconnect;

                        _instance = nxserverlib_init_extended(&_serverSettings, config.Authentication.Value());
                        if (_instance == nullptr) {
                            result = Core::ERROR_UNAVAILABLE;
                        }
                        else {
                            rc = nxserver_ipc_init(_instance, _lock);

                            if (rc != NEXUS_SUCCESS) {
                                result = Core::ERROR_RPC_CALL_FAILED;
                            }
                            else {
                                result = Core::ERROR_NONE;
                                TRACE(Trace::Information, (_T("PID[%d] Creating NXServer."), getpid()));

                                // fake config.HWDelay.Value() miliseconds hardware initiation time.
                                uint32_t sleep = config.HWDelay.Value();
                                _job.Initialize(sleep * 1000);
                            }
                        }
                    }
                }
            }

            g_lock.Unlock();

            StateChange(result == Core::ERROR_NONE ? Exchange::IPlatform::INITIALIZING : Exchange::IPlatform::FAILURE);

            ASSERT(_state != Exchange::IPlatform::FAILURE);

            if (_state != Exchange::IPlatform::FAILURE) {

                // fake config.HWDelay.Value() miliseconds hardware initiation time.
                uint32_t sleep = config.HWDelay.Value();
                _job.Initialize(sleep * 1000);

                TRACE(Trace::Information, (_T("PlatformImplementation busy initializing (delay: %d)"), sleep));
            }
        }
        virtual Exchange::IPlatform::server_state State() const override
        {
            return _state;
        }

    private:
        // -------------------------------------------------------------------------------------------------------
        //   private methods
        // -------------------------------------------------------------------------------------------------------
        void PlatformReady()
        {
            // The platform appears to be ready, set the event
            PluginHost::ISubSystem* subSystem = _service->SubSystems();

            ASSERT(subSystem != nullptr);

            if (subSystem != nullptr) {
                subSystem->Set(PluginHost::ISubSystem::PLATFORM, nullptr);
                subSystem->Release();
            }


            StateChange(Exchange::IPlatform::OPERATIONAL);
        }

        void Add(nxclient_t client, const NxClient_JoinSettings* joinSettings)
        {
            if (_clientHandler != nullptr) {
                _clientHandler->Attached(client, joinSettings);
            }
        }
        void Remove(const char clientName[])
        {
            if (_clientHandler != nullptr) {
                _clientHandler->Detached(clientName);
            }
        }

        void StateChange(Exchange::IPlatform::server_state state){
            _state = state;

            if (_clientHandler != nullptr) {
                _clientHandler->StateChange(_state);
            }
        };

        static int ClientConnect(nxclient_t client, const NxClient_JoinSettings* pJoinSettings, NEXUS_ClientSettings* pClientSettings)
        {
            BSTD_UNUSED(pClientSettings);

            // Make sure we get exclusive access to the Resource Center.
            g_lock.Lock();

            if (g_instance != nullptr) {

                /* server app has opportunity to reject client altogether, or modify pClientSettings */
                g_instance->Add(client, pJoinSettings);
            }

            g_lock.Unlock();

            return (0);
        }
        static void ClientDisconnect(nxclient_t client, const NxClient_JoinSettings* pJoinSettings)
        {
            BSTD_UNUSED(pJoinSettings);

            // Make sure we get exclusive access to the Resource Center.
            g_lock.Lock();

            if (g_instance != nullptr) {

                g_instance->Remove(pJoinSettings->name);
            }

            g_lock.Unlock();
        }
        static void CloseDown()
        {
            // Make sure we get exclusive access to the Destruction of this Resource Center.
            g_lock.Lock();

            // Seems we are destructed.....If we still have a pointer to the implementation, Kill it..
            if (g_instance != nullptr) {
                delete g_instance;
                g_instance = nullptr;
            }
            g_lock.Unlock();
        }

    private:
        BKNI_MutexHandle _lock;
        nxserver_t _instance;
        nxserver_settings _serverSettings;
        NEXUS_PlatformSettings _platformSettings;
        NEXUS_PlatformCapabilities _platformCapabilities;
        NxClient_JoinSettings _joinSettings;
        Job _job;
        PluginHost::IShell* _service;
        Exchange::IPlatform::server_state _state;
        std::list<Entry*> _nexusClients;
        mutable ICallback* _clientHandler;
    };
}

namespace Exchange {
    /* static */ IPlatform* IPlatform::Instance()
    {
        static  Broadcom::PlatformImplementation instance;

        return &instance;
    }
} // namespace Platform
}