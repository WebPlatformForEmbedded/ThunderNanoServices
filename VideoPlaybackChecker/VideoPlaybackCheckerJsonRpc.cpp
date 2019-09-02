
#include "Module.h"
#include "VideoPlaybackChecker.h"
#include <interfaces/json/JsonData_VideoPlaybackChecker.h>

/*
    // Copy the code below to VideoPlaybackChecker class definition
    // Note: The VideoPlaybackChecker class must inherit from PluginHost::JSONRPC

    private:
        void RegisterAll();
        void UnregisterAll();
        uint32_t endpoint_play(const JsonData::VideoPlaybackChecker::PlayParamsData& params);
*/

namespace WPEFramework {

namespace Plugin {

    using namespace JsonData::VideoPlaybackChecker;

    // Registration
    //

    void VideoPlaybackChecker::RegisterAll()
    {
        Register<PlayParamsData,void>(_T("play"), &VideoPlaybackChecker::endpoint_play, this);
    }

    void VideoPlaybackChecker::UnregisterAll()
    {
        Unregister(_T("play"));
    }

    // API implementation
    //

    // Method: play - Starts the playback of desired file
    // Return codes:
    //  - ERROR_NONE: Success
    //  - ERROR_BAD_REQUEST: Bad JSON param data format
    uint32_t VideoPlaybackChecker::endpoint_play(const PlayParamsData& params)
    {
        uint32_t result = Core::ERROR_NONE;
        const string& source = params.Source.Value();
        const bool& withOCDM = params.WithOCDM.Value();

        printf("**************** endpoint_play ******************\n");
        if(params.Source.IsSet() != true) {
            printf("**************** Source.IsSet() ******************\n");
            result = Core::ERROR_UNAVAILABLE;
            return result;
        }

        if(params.WithOCDM.IsSet() != true) {
            printf("**************** WithOCDM.IsSet() ******************\n");
            result = Core::ERROR_UNAVAILABLE;
            return result;
        }

        if(_VideoPlaybackCheckerImpl){
            _VideoPlaybackCheckerImpl->Play(source, withOCDM);
        } else {
            printf("**************** no implementation !!! ******************\n");
            result = Core::ERROR_UNAVAILABLE;
        }

        return result;
    }

} // namespace Plugin

}

