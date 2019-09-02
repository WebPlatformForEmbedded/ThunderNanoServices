#include "Module.h"

#include <interfaces/IPlay.h>

#include "prdy30_svp.h"

namespace WPEFramework {
namespace TestCore {

    class VideoPlaybackCheckerImpl : public Exchange::IPlay {
    public:
        VideoPlaybackCheckerImpl(const VideoPlaybackCheckerImpl&) = delete;
        VideoPlaybackCheckerImpl& operator=(const VideoPlaybackCheckerImpl&) = delete;

    public:
        VideoPlaybackCheckerImpl() = default;

        virtual ~VideoPlaybackCheckerImpl() = default;

        //  IPlay methods
        // -------------------------------------------------------------------------------------------------------
        void Play(const string& source, bool withOCDM) const override
        {
            printf("**************** PLAY (ts: %s, withOCDM: %d)******************\n", source.c_str(), withOCDM);
            char *args[] = {"", source.c_str()};
            if(!withOCDM) {
                start(2, args);
            } else {
                printf("**************** witOCDM path******************\n");
            }
        }

        BEGIN_INTERFACE_MAP(VideoPlaybackCheckerImpl)
        INTERFACE_ENTRY(Exchange::IPlay)
        END_INTERFACE_MAP
    };

    SERVICE_REGISTRATION(VideoPlaybackCheckerImpl, 1, 0);
} // namespace TestCore
} // namespace WPEFramewor
