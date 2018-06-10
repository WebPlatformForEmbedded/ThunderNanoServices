#ifndef IBROADCOM_H
#define IBROADCOM_H

#include <core.h>
#include <plugins.h>
#include <nexus_config.h>
#include <nxserverlib.h>

namespace WPEFramework {
    namespace Exchange {
        struct IPlatform {

            enum server_state {
                FAILURE = 0,
                UNITIALIZED,
                INITIALIZING,
                OPERATIONAL,
                DEINITIALIZING,
            };

            struct ICallback {
                virtual ~ICallback() {}
                virtual void Attached(nxclient_t client, const NxClient_JoinSettings* pJoinSettings) = 0;
                virtual void Detached(const char clientName[])= 0;

                // Signal changes on the subscribed namespace..
                virtual void StateChange(server_state state) = 0;
            };

            virtual ~IPlatform(){};

            virtual void Callback(ICallback* callback) const = 0 ;

            virtual uint32_t Configure(PluginHost::IShell* service) = 0;

            virtual server_state State() const = 0;

            static IPlatform* Instance();
        };
    }
}
#endif //IBROADCOM_H
