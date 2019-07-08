//I have put several "TODO(MROLLINS)" in the code below to mark areas of concern I encountered 
//  when refactoring the servicemanager's version of displaysettings into this new thunder plugin format

#include "DisplaySettings.h"
#include <algorithm>
#include "dsMgr.h"
#include "libIBusDaemon.h"
#include "host.hpp"
#include "exception.hpp"
#include "videoOutputPort.hpp"
#include "videoOutputPortType.hpp"
#include "videoOutputPortConfig.hpp"
#include "videoResolution.hpp"
#include "audioOutputPort.hpp"
#include "audioOutputPortType.hpp"
#include "audioOutputPortConfig.hpp"
#include "manager.hpp"
#include "dsUtl.h"
#include "dsError.h"
#include "list.hpp"
#include "libIBus.h"
#include "dsDisplay.h"
#include "rdk/iarmmgrs-hal/pwrMgr.h"

//TODO(MROLLINS) - i'm doing fprintf to /opt/logs/ds.log now for simplicity and easy debugging
//but eventually these log macros need to call the wpe logger instead of fprintf.  
#define MYLOG(...) fprintf(logger, __VA_ARGS__); fflush(logger);
#define MYWARN(...) fprintf(logger, __VA_ARGS__); fflush(logger);
#define MYERROR(...) fprintf(logger, __VA_ARGS__); fflush(logger);
#define MYTRACEMETHOD() { string json; parameters.ToString(json); fprintf(logger, "%s parameters=%s\n", __FUNCTION__, json.c_str() ); fflush(logger); }
#define MYTRACEMETHODFIN() { string json; response.ToString(json); fprintf(logger, "%s response=%s\n", __FUNCTION__, json.c_str() ); fflush(logger); }
#define MYTRACE() fprintf(logger, "%s\n", __PRETTY_FUNCTION__); fflush(logger);
#define LOG_DEVICE_EXCEPTION0() MYWARN("Exception caught while processing %s code=%d message=%s\n", __FUNCTION__, err.getCode(), err.what());
#define LOG_DEVICE_EXCEPTION1(param1) MYWARN("Exception caught while processing %s " #param1 "=%s code=%d message=%s\n", __FUNCTION__, param1.c_str(), err.getCode(), err.what());
#define LOG_DEVICE_EXCEPTION2(param1,param2) MYWARN("Exception caught while processing %s " #param1 "=%s " #param2 "=%s code=%d message=%s\n", __FUNCTION__, param1.c_str(), param2.c_str(), err.getCode(), err.what());

//this set of macros are used in the method handlers to make the code more consistent and easier to read
#define vectorSet(v,s) \
    if (find(begin(v), end(v), s) == end(v)) \
        v.emplace_back(s);
#define stringContains(s1,s2) \
    (search(s1.begin(), s1.end(), s2, s2+strlen(s2), \
        [](char c1, char c2){ \
            return toupper(c1) == toupper(c2); \
    }) != s1.end())
#define returnResponse(success) \
    response["success"] = success; \
    MYTRACEMETHODFIN(); \
    return (Core::ERROR_NONE); 
#define returnIfWrongApiVersion(version)\
    if(getApiVersionNumber() < version)\
    {\
        MYWARN("method %s not supported. version required=%u actual=%u\n", __FUNCTION__, version, getApiVersionNumber());\
        returnResponse(false);\
    }
#define returnIfParamNotFound(param)\
    if(param.empty())\
    {\
        MYWARN("method %s missing parameter %s\n", __FUNCTION__, #param);\
        returnResponse(false);\
    }

#define sendNotify(event,params)\
    string json;\
    params.ToString(json);\
    MYLOG("Notify %s %s\n", event, json.c_str());\
    Notify(event,params);
    
#define IARM_CHECK(FUNC) \
  if ((res = FUNC) != IARM_RESULT_SUCCESS) { \
    MYLOG("DisplaySettings %s: %s\n", #FUNC, \
        res == IARM_RESULT_INVALID_PARAM ? "invalid param" : ( \
        res == IARM_RESULT_INVALID_STATE ? "invalid state" : ( \
        res == IARM_RESULT_IPCCORE_FAIL ? "ipcore fail" : ( \
        res == IARM_RESULT_OOM ? "oom" : "unknown")))); \
  } else { \
    MYLOG("DisplaySettings %s: success\n", #FUNC); \
  }

#define HDMI_HOT_PLUG_EVENT_CONNECTED 0

#define USE_IARM //TODO(MROLLINS) - this was defined in servicemanager.pro for all STB builds.  Not sure where to put it except here for now

#ifdef USE_IARM 
namespace
{
	/**
	 * @struct Mapping
	 * @brief Structure that defines members for the display setting service.
	 * @ingroup SERVMGR_DISPSETTINGS
	 */
    struct Mapping
    {
        const char *IArmBusName;
        const char *SvcManagerName;
    };

    static struct Mapping name_mappings[] = {
        { "Full", "FULL" },
        { "None", "NONE" },
        { "mono", "MONO" },
        { "stereo", "STEREO" },
        { "surround", "SURROUND" },
        { "unknown", "UNKNOWN" },
        // TODO: add your mappings here
        // { <IARM_NAME>, <SVC_MANAGER_API_NAME> },
        { 0,  0 }
    };

    string svc2iarm(const string &name)
    {
        const char *s = name.c_str();

        int i = 0;
        while (name_mappings[i].SvcManagerName)
        {
            if (strcmp(s, name_mappings[i].SvcManagerName) == 0)
                return name_mappings[i].IArmBusName;
            i++;
        }
        return name;
    }

    string iarm2svc(const string &name)
    {
        const char *s = name.c_str();

        int i = 0;
        while (name_mappings[i].IArmBusName)
        {
            if (strcmp(s, name_mappings[i].IArmBusName) == 0)
                return name_mappings[i].SvcManagerName;
            i++;
        }
        return name;
    }
}
#endif

namespace WPEFramework {

	namespace Plugin {

        static FILE* logger = nullptr;
        
        SERVICE_REGISTRATION(DisplaySettings, 1, 0);

        DisplaySettings* DisplaySettings::_instance = nullptr;

		DisplaySettings::DisplaySettings()
			: PluginHost::JSONRPC()
			, m_apiVersionNumber((uint32_t)-1/*default max uint32_t so everything gets enabled*/)//TODO(MROLLINS) Can't we access this from jsonrpc interface?
		{
    		logger = fopen("/opt/logs/ds.log", "w");
    		
            MYTRACE();
            DisplaySettings::_instance = this;
   			Register("getQuirks", &DisplaySettings::getQuirks, this);
			Register("getConnectedVideoDisplays", &DisplaySettings::getConnectedVideoDisplays, this);
			Register("getConnectedAudioPorts", &DisplaySettings::getConnectedAudioPorts, this);
			Register("getSupportedResolutions", &DisplaySettings::getSupportedResolutions, this);
			Register("getSupportedVideoDisplays", &DisplaySettings::getSupportedVideoDisplays, this);			
			Register("getSupportedTvResolutions", &DisplaySettings::getSupportedTvResolutions, this);
			Register("getSupportedSettopResolutions", &DisplaySettings::getSupportedSettopResolutions, this);			
			Register("getSupportedAudioPorts", &DisplaySettings::getSupportedAudioPorts, this);
			Register("getSupportedAudioModes", &DisplaySettings::getSupportedAudioModes, this);
			Register("getZoomSetting", &DisplaySettings::getZoomSetting, this);
			Register("setZoomSetting", &DisplaySettings::setZoomSetting, this);
			Register("getCurrentResolution", &DisplaySettings::getCurrentResolution, this);
			Register("setCurrentResolution", &DisplaySettings::setCurrentResolution, this);
			Register("getSoundMode", &DisplaySettings::getSoundMode, this);
			Register("setSoundMode", &DisplaySettings::setSoundMode, this);
			Register("readEDID", &DisplaySettings::readEDID, this);
			Register("readHostEDID", &DisplaySettings::readHostEDID, this);
			Register("getActiveInput", &DisplaySettings::getActiveInput, this);
			Register("getTvHDRSupport", &DisplaySettings::getTvHDRSupport, this);
			Register("getSettopHDRSupport", &DisplaySettings::getSettopHDRSupport, this);
			Register("setVideoPortStatusInStandby", &DisplaySettings::setVideoPortStatusInStandby, this);
			Register("getVideoPortStatusInStandby", &DisplaySettings::getVideoPortStatusInStandby, this);
			
			setApiVersionNumber(7);//TODO(MROLLINS) - this is suppose to be called from xre receiver in DisplaySettingsAPI ctor, but we need to get it from the jsonrpc client version
		}
		DisplaySettings::~DisplaySettings()
		{
            MYTRACE();
            DisplaySettings::_instance = nullptr;
			Unregister("getQuirks");
			Unregister("getConnectedVideoDisplays");
			Unregister("getConnectedAudioPorts");
			Unregister("getSupportedResolutions");
			Unregister("getSupportedVideoDisplays");
			Unregister("getSupportedTvResolutions");
			Unregister("getSupportedSettopResolutions");			
			Unregister("getSupportedAudioPorts");
			Unregister("getSupportedAudioModes");
			Unregister("getZoomSetting");
			Unregister("setZoomSetting");
			Unregister("getCurrentResolution");
			Unregister("setCurrentResolution");
			Unregister("getSoundMode");
			Unregister("setSoundMode");
			Unregister("readEDID");
			Unregister("readHostEDID");
			Unregister("getActiveInput");
			Unregister("getTvHDRSupport");
			Unregister("getSettopHDRSupport");
			Unregister("setVideoPortStatusInStandby");
			Unregister("getVideoPortStatusInStandby");
		}
		const string DisplaySettings::Initialize(PluginHost::IShell* /* service */)
		{
            MYTRACE();
            InitializeIARM();
			// On success return empty, to indicate there is no error text.
			return (string());
		}
		void DisplaySettings::Deinitialize(PluginHost::IShell* /* service */)
		{
            MYTRACE();
            DeinitializeIARM();
		}
		string DisplaySettings::Information() const
		{
			// No additional info to report.
			return (string());
		}
        void DisplaySettings::InitializeIARM()
        {
            MYTRACE();
            IARM_Result_t res;
            IARM_CHECK( IARM_Bus_Init("Display_Settings") );
            IARM_CHECK( IARM_Bus_Connect() );
            IARM_CHECK( IARM_Bus_RegisterEventHandler(IARM_BUS_DSMGR_NAME, IARM_BUS_DSMGR_EVENT_RX_SENSE, DisplResolutionHandler) );
            IARM_CHECK( IARM_Bus_RegisterEventHandler(IARM_BUS_DSMGR_NAME, IARM_BUS_DSMGR_EVENT_ZOOM_SETTINGS, DisplResolutionHandler) );
            //TODO(MROLLINS) localinput.cpp has PreChange guared with #if !defined(DISABLE_PRE_RES_CHANGE_EVENTS)
            //Can we set it all the time from inside here and let localinput put guards around listening for our event?
            IARM_CHECK( IARM_Bus_RegisterCall(IARM_BUS_COMMON_API_ResolutionPreChange, ResolutionPreChange) );
            IARM_CHECK( IARM_Bus_RegisterCall(IARM_BUS_COMMON_API_ResolutionPostChange, ResolutionPostChange) );
            IARM_CHECK( IARM_Bus_RegisterEventHandler(IARM_BUS_DSMGR_NAME,IARM_BUS_DSMGR_EVENT_HDMI_HOTPLUG, dsHdmiEventHandler) );
            try
            {
                //TODO(MROLLINS) this is probably per process so we either need to be running in our own process or be carefull no other plugin is calling it
                device::Manager::Initialize();
                MYLOG("device::Manager::Initialize success\n");
            }
            catch(...)
            {
                MYLOG("device::Manager::Initialize failed\n");            
            }
        }
        //TODO(MROLLINS) - we need to install crash handler to ensure DeinitializeIARM gets called
        void DisplaySettings::DeinitializeIARM()
        {
            MYTRACE();
            IARM_Result_t res;        
            IARM_CHECK( IARM_Bus_UnRegisterEventHandler(IARM_BUS_DSMGR_NAME, IARM_BUS_DSMGR_EVENT_RX_SENSE) );
            IARM_CHECK( IARM_Bus_UnRegisterEventHandler(IARM_BUS_DSMGR_NAME, IARM_BUS_DSMGR_EVENT_ZOOM_SETTINGS) );
            IARM_CHECK( IARM_Bus_Disconnect() );
            IARM_CHECK( IARM_Bus_Term() );
            try
            {
                //TODO(MROLLINS) this is probably per process so we either need to be running in our own process or be carefull no other plugin is calling it
                device::Manager::DeInitialize();
                MYLOG("device::Manager::DeInitialize success\n");
            }
            catch(...)
            {
                MYLOG("device::Manager::DeInitialize failed\n");            
            }
            
        }
		IARM_Result_t DisplaySettings::ResolutionPreChange(void *arg)
		{
            MYTRACE();
            if(DisplaySettings::_instance)
            {
                DisplaySettings::_instance->resolutionPreChange();		
            }
    		return IARM_RESULT_SUCCESS;
		}
		IARM_Result_t DisplaySettings::ResolutionPostChange(void *arg)
		{
            MYTRACE();		
            int dw = 1280;
            int dh = 720;
            IARM_Bus_CommonAPI_ResChange_Param_t *eventData = (IARM_Bus_CommonAPI_ResChange_Param_t *)arg;
            dw = eventData->width;
            dh = eventData->height;
            if(DisplaySettings::_instance)
            {
                DisplaySettings::_instance->resolutionChanged(dw,dh);		
            }
    		return IARM_RESULT_SUCCESS;
        }
        void DisplaySettings::DisplResolutionHandler(const char *owner, IARM_EventId_t eventId, void *data, size_t len)
        {
            MYTRACE();        
            //TODO(MROLLINS) Receiver has this whole thing guarded by #ifndef HEADLESS_GW
            if (strcmp(owner,IARM_BUS_DSMGR_NAME) == 0)
            {
                switch (eventId)
                {
                case IARM_BUS_DSMGR_EVENT_RES_PRECHANGE:
                    break;
                case IARM_BUS_DSMGR_EVENT_RES_POSTCHANGE:
                    {
                        int dw = 1280;
                        int dh = 720;
                        IARM_Bus_DSMgr_EventData_t *eventData = (IARM_Bus_DSMgr_EventData_t *)data;
                        dw = eventData->data.resn.width ;
                        dh = eventData->data.resn.height ;
                        if(DisplaySettings::_instance)
                            DisplaySettings::_instance->resolutionChanged(dw,dh);
                    }
                    break;
                case IARM_BUS_DSMGR_EVENT_ZOOM_SETTINGS:
                    {
                        IARM_Bus_DSMgr_EventData_t *eventData = (IARM_Bus_DSMgr_EventData_t *)data;
                        if(eventData->data.dfc.zoomsettings == dsVIDEO_ZOOM_NONE)
                        {
                            MYLOG("%s: dsVIDEO_ZOOM_NONE Settings\n",__FUNCTION__);
                            if(DisplaySettings::_instance)
                                DisplaySettings::_instance->zoomSettingUpdated("NONE");
                        }
                        else if(eventData->data.dfc.zoomsettings == dsVIDEO_ZOOM_FULL)
                        {
                            MYLOG("%s: dsVIDEO_ZOOM_FULL Settings\n",__FUNCTION__);
                            if(DisplaySettings::_instance)
                                DisplaySettings::_instance->zoomSettingUpdated("FULL");
                        }
                    }
                    break;
                case IARM_BUS_DSMGR_EVENT_RX_SENSE:
                    {
                        
                        IARM_Bus_DSMgr_EventData_t *eventData = (IARM_Bus_DSMgr_EventData_t *)data;
                        if(eventData->data.hdmi_rxsense.status == dsDISPLAY_RXSENSE_ON)
                        {
                            MYLOG("%s: Got dsDISPLAY_RXSENSE_ON -> notifyactiveInputChanged(true)\n",__FUNCTION__);
                            if(DisplaySettings::_instance)
                                DisplaySettings::_instance->activeInputChanged(true);
                        }
                        else if(eventData->data.hdmi_rxsense.status == dsDISPLAY_RXSENSE_OFF)
                        {
                            MYLOG("%s: Got dsDISPLAY_RXSENSE_OFF -> notifyactiveInputChanged(false)\n",__FUNCTION__);
                            if(DisplaySettings::_instance)
                                DisplaySettings::_instance->activeInputChanged(false);
                        }
                    }
                    break;
                default:
                    break;
                }
            }
        }
        void DisplaySettings::dsHdmiEventHandler(const char *owner, IARM_EventId_t eventId, void *data, size_t len)
        {
            MYTRACE();        
            switch (eventId)
            {
            case IARM_BUS_DSMGR_EVENT_HDMI_HOTPLUG : 
                //TODO(MROLLINS) note that there are several services listening for the notifyHdmiHotPlugEvent ServiceManagerNotifier broadcast
                //So if DisplaySettings becomes the owner/originator of this, then those future thunder plugins need to listen to our event
                //But of course, nothing is stopping any thunder plugin for listening to iarm event directly -- this is getting murky
                {
                    IARM_Bus_DSMgr_EventData_t *eventData = (IARM_Bus_DSMgr_EventData_t *)data;
                    int hdmi_hotplug_event = eventData->data.hdmi_hpd.event;
                    MYLOG("Received IARM_BUS_DSMGR_EVENT_HDMI_HOTPLUG  event data:%d \r\n", hdmi_hotplug_event);
                    if(DisplaySettings::_instance)
                        DisplaySettings::_instance->connectedVideoDisplaysUpdated(hdmi_hotplug_event);
                }
                break;
                //TODO(MROLLINS) localinput.cpp was also sending these and they were getting handled by services other then DisplaySettings.  Should DisplaySettings own these as well ?
                /*    
            case IARM_BUS_DSMGR_EVENT_HDMI_IN_HOTPLUG : 
                {
                    IARM_Bus_DSMgr_EventData_t *eventData = (IARM_Bus_DSMgr_EventData_t *)data;
                    int hdmiin_hotplug_port = eventData->data.hdmi_in_connect.port;
                    int hdmiin_hotplug_conn = eventData->data.hdmi_in_connect.isPortConnected;
                    MYLOG("Received IARM_BUS_DSMGR_EVENT_HDMI_IN_HOTPLUG  event data:%d, %d \r\n", hdmiin_hotplug_port);
                    ServiceManagerNotifier::getInstance()->notifyHdmiInputHotPlugEvent(hdmiin_hotplug_port, hdmiin_hotplug_conn);
                }
                break;
            case IARM_BUS_DSMGR_EVENT_HDCP_STATUS : 
                {
                    IARM_Bus_DSMgr_EventData_t *eventData = (IARM_Bus_DSMgr_EventData_t *)data;
                    int hdcpStatus = eventData->data.hdmi_hdcp.hdcpStatus;
                    MYLOG("Received IARM_BUS_DSMGR_EVENT_HDCP_STATUS  event data:%d \r\n", hdcpStatus);
                    ServiceManagerNotifier::getInstance()->notifyHdmiOutputHDCPStatus(hdcpStatus);
                }
                break;	
                */                
            default:
                //do nothing
                break;
            }
        }        
        void setResponseArray(JsonObject& response, const char* key, const vector<string>& items)
        {
            JsonArray arr;
            for(auto& i : items)
            {
                MYLOG("%s adding %s\n", key, i.c_str());
                arr.Add(JsonValue(i));
            }
            response[key] = arr;
        }
        uint32_t DisplaySettings::getQuirks(const JsonObject& parameters, JsonObject& response)
        {
            MYTRACEMETHOD();
            JsonArray array;
            array.Add("XRE-7389");
            array.Add("DELIA-16415");
            array.Add("RDK-16024");
            array.Add("DELIA-18552");
            response["quirks"] = array;
            returnResponse(true);
        }
        uint32_t DisplaySettings::getConnectedVideoDisplays(const JsonObject& parameters, JsonObject& response)
        {   //sample servicemanager response: {"connectedVideoDisplays":["HDMI0"],"success":true}
            //this                          : {"connectedVideoDisplays":["HDMI0"]}
            MYTRACEMETHOD();
            vector<string> connectedVideoDisplays;
            getConnectedVideoDisplaysHelper(connectedVideoDisplays);
            setResponseArray(response, "connectedVideoDisplays", connectedVideoDisplays);
            returnResponse(true);
        }
        uint32_t DisplaySettings::getConnectedAudioPorts(const JsonObject& parameters, JsonObject& response)
        {   //sample servicemanager response: {"success":true,"connectedAudioPorts":["HDMI0"]}
            MYTRACEMETHOD();
            vector<string> connectedAudioPorts;
            try
            {
                device::List<device::AudioOutputPort> aPorts = device::Host::getInstance().getAudioOutputPorts();
                for (size_t i = 0; i < aPorts.size(); i++)
                {
                    device::AudioOutputPort &aPort = aPorts.at(i);
                    if (aPort.isConnected())
                    {
                        string portName = aPort.getName();
                        vectorSet(connectedAudioPorts, portName);
                    }
                }
            }
            catch(const device::Exception& err)
            {
                LOG_DEVICE_EXCEPTION0();
            }             
            setResponseArray(response, "connectedAudioPorts", connectedAudioPorts);
            returnResponse(true);
        }
        uint32_t DisplaySettings::getSupportedResolutions(const JsonObject& parameters, JsonObject& response)
        {   //sample servicemanager response:{"success":true,"supportedResolutions":["720p","1080i","1080p60"]}
            MYTRACEMETHOD();
            string videoDisplay = parameters.HasLabel("videoDisplay") ? parameters["videoDisplay"].String() : "HDMI0";
            vector<string> supportedResolutions;
            try
            {
                device::VideoOutputPort &vPort = device::Host::getInstance().getVideoOutputPort(videoDisplay);
                const device::List<device::VideoResolution> resolutions = device::VideoOutputPortConfig::getInstance().getPortType(vPort.getType().getId()).getSupportedResolutions();
                for (size_t i = 0; i < resolutions.size(); i++) {
                    const device::VideoResolution &resolution = resolutions.at(i);
                    string supportedResolution = resolution.getName();
                    vectorSet(supportedResolutions,supportedResolution);
                }
            }
            catch(const device::Exception& err)
            {
                LOG_DEVICE_EXCEPTION1(videoDisplay);
            }
            setResponseArray(response, "supportedResolutions", supportedResolutions);
            returnResponse(true);
        }
        uint32_t DisplaySettings::getSupportedVideoDisplays(const JsonObject& parameters, JsonObject& response)
        {   //sample servicemanager response: {"supportedVideoDisplays":["HDMI0"],"success":true}
            MYTRACEMETHOD();
            vector<string> supportedVideoDisplays;
            try
            {
                device::List<device::VideoOutputPort> vPorts = device::Host::getInstance().getVideoOutputPorts();
                for (size_t i = 0; i < vPorts.size(); i++)
                {
                    device::VideoOutputPort &vPort = vPorts.at(i);
                    string videoDisplay = vPort.getName();
                    vectorSet(supportedVideoDisplays, videoDisplay);
                }
            }
            catch (const device::Exception& err)
            {
                LOG_DEVICE_EXCEPTION0();
            }
            setResponseArray(response, "supportedVideoDisplays", supportedVideoDisplays);
            returnResponse(true);
        }
        uint32_t DisplaySettings::getSupportedTvResolutions(const JsonObject& parameters, JsonObject& response)
        {   //sample servicemanager response:{"success":true,"supportedTvResolutions":["480i","480p","576i","720p","1080i","1080p"]}
            MYTRACEMETHOD();
            returnIfWrongApiVersion(6);
            string videoDisplay = parameters.HasLabel("videoDisplay") ? parameters["videoDisplay"].String() : "HDMI0";
            vector<string> supportedTvResolutions;
            try
            {
                int tvResolutions = 0;
                device::VideoOutputPort &vPort = device::Host::getInstance().getVideoOutputPort(videoDisplay);
                vPort.getSupportedTvResolutions(&tvResolutions);
                if(!tvResolutions)supportedTvResolutions.emplace_back("none");
                if(tvResolutions & dsTV_RESOLUTION_480i)supportedTvResolutions.emplace_back("480i");
                if(tvResolutions & dsTV_RESOLUTION_480p)supportedTvResolutions.emplace_back("480p");
                if(tvResolutions & dsTV_RESOLUTION_576i)supportedTvResolutions.emplace_back("576i");
                if(tvResolutions & dsTV_RESOLUTION_576p)supportedTvResolutions.emplace_back("576p");
                if(tvResolutions & dsTV_RESOLUTION_720p)supportedTvResolutions.emplace_back("720p");
                if(tvResolutions & dsTV_RESOLUTION_1080i)supportedTvResolutions.emplace_back("1080i");
                if(tvResolutions & dsTV_RESOLUTION_1080p)supportedTvResolutions.emplace_back("1080p");
                if(tvResolutions & dsTV_RESOLUTION_2160p30)supportedTvResolutions.emplace_back("2160p30");
                if(tvResolutions & dsTV_RESOLUTION_2160p60)supportedTvResolutions.emplace_back("2160p60");
            }
            catch(const device::Exception& err)
            {
                LOG_DEVICE_EXCEPTION1(videoDisplay);
            }
            setResponseArray(response, "supportedTvResolutions", supportedTvResolutions);
            returnResponse(true);
        }
        uint32_t DisplaySettings::getSupportedSettopResolutions(const JsonObject& parameters, JsonObject& response)
        {   //sample servicemanager response:{"success":true,"supportedSettopResolutions":["720p","1080i","1080p60"]}
            MYTRACEMETHOD();
            returnIfWrongApiVersion(6);
            std::vector<string> supportedSettopResolutions;
            try
            {
                device::VideoDevice &device = device::Host::getInstance().getVideoDevices().at(0);
                std::list<std::string> resolutions;
                device.getSettopSupportedResolutions(resolutions);
                for (std::list<std::string>::const_iterator ci = resolutions.begin(); ci != resolutions.end(); ++ci)
                {
                      string supportedResolution = *ci;
                      vectorSet(supportedSettopResolutions, supportedResolution);
                }
            }
            catch(const device::Exception& err)
            {
                LOG_DEVICE_EXCEPTION0();
            }             
            setResponseArray(response, "supportedSettopResolutions", supportedSettopResolutions);
            returnResponse(true);
        }
        uint32_t DisplaySettings::getSupportedAudioPorts(const JsonObject& parameters, JsonObject& response)
        {   //sample servicemanager response: {"success":true,"supportedAudioPorts":["HDMI0"]}
            MYTRACEMETHOD();
            vector<string> supportedAudioPorts;
            try
            {
                device::List<device::AudioOutputPort> aPorts = device::Host::getInstance().getAudioOutputPorts();
                for (size_t i = 0; i < aPorts.size(); i++)
                {
                    device::AudioOutputPort &vPort = aPorts.at(i);
                    string portName  = vPort.getName();
                    vectorSet(supportedAudioPorts,portName);
                }
            }
            catch(const device::Exception& err)
            {
                LOG_DEVICE_EXCEPTION0();
            }
            setResponseArray(response, "supportedAudioPorts", supportedAudioPorts);
            returnResponse(true);
        }
        uint32_t DisplaySettings::getSupportedAudioModes(const JsonObject& parameters, JsonObject& response)
        {   //sample response: {"success":true,"supportedAudioModes":["STEREO","PASSTHRU","AUTO (Dolby Digital 5.1)"]}
            MYTRACEMETHOD();
            returnIfWrongApiVersion(2);
            string audioPort = parameters["audioPort"].String();
            vector<string> supportedAudioModes;
            try
            {
                bool HAL_hasSurround = false;
                
                device::List<device::VideoOutputPort> vPorts = device::Host::getInstance().getVideoOutputPorts();
                for (size_t i = 0; i < vPorts.size(); i++) {
                    device::AudioOutputPort &aPort = vPorts.at(i).getAudioOutputPort();
                    for (size_t i = 0; i < aPort.getSupportedStereoModes().size(); i++) {
                        if (audioPort.empty() || stringContains(aPort.getName(), audioPort.c_str()))
                        {
                            string audioMode = aPort.getSupportedStereoModes().at(i).getName();
                            
                            // Starging Version 5, "Surround" mode is replaced by "Auto Mode"
                            if ((getApiVersionNumber() >= 5) && (strcasecmp(audioMode.c_str(),"SURROUND") == 0)) 
                            {
                                HAL_hasSurround = true;
                                continue;
                            }

                            if ((getApiVersionNumber() < 5) && (strcasecmp(audioMode.c_str(),"PASSTHRU") == 0)) 
                            {
                                /* Do not support PASSTHRU in DS 4 or lower */
                                continue;
                            }

                            vectorSet(supportedAudioModes,audioMode);
                        }
                    }
                }
                /* Version 5: Append Auto Mode for HDMI ports*/
                if (getApiVersionNumber() >= 5 && (audioPort.empty() || stringContains(audioPort, "HDMI")))
                {
                    device::VideoOutputPort vPort = device::VideoOutputPortConfig::getInstance().getPort("HDMI0");
                    int surroundMode = vPort.getDisplay().getSurroundMode();
                    if (vPort.isDisplayConnected() && surroundMode)
                    {
                        if(surroundMode & dsSURROUNDMODE_DDPLUS )
                        {
                            MYLOG("HDMI0 has surround DD Plus \n");
                            supportedAudioModes.emplace_back("AUTO (Dolby Digital Plus)");
                        }
                        else if(surroundMode & dsSURROUNDMODE_DD )
                        {
                            MYLOG("HDMI0 has surround DD5.1 \n");
                            supportedAudioModes.emplace_back("AUTO (Dolby Digital 5.1)");
                        }
                    }
                    else {
                        MYLOG("HDMI0 does not have surround\n");
                        supportedAudioModes.emplace_back("AUTO (Stereo)");
                    }
                }
                if (getApiVersionNumber() >= 5 && (audioPort.empty() || stringContains(audioPort, "SPDIF")))
                {
                    if (HAL_hasSurround) {
                        supportedAudioModes.emplace_back("Surround");
                    }
                }
            }
            catch(const device::Exception& err)
            {
                LOG_DEVICE_EXCEPTION1(audioPort);
            }
            setResponseArray(response, "supportedAudioModes", supportedAudioModes);
            returnResponse(true);
        }
        uint32_t DisplaySettings::getZoomSetting(const JsonObject& parameters, JsonObject& response)
        {   //sample servicemanager response:
            MYTRACEMETHOD();
            string zoomSetting = "unknown";
            try
            {
                // TODO: why is this always the first one in the list
                device::VideoDevice &decoder = device::Host::getInstance().getVideoDevices().at(0);
                zoomSetting = decoder.getDFC().getName();
            }
            catch(const device::Exception& err)
            {
                LOG_DEVICE_EXCEPTION0();
            }
#ifdef USE_IARM
            zoomSetting = iarm2svc(zoomSetting);
#endif
            response["zoomSetting"] = zoomSetting;
            returnResponse(true);
        }
        uint32_t DisplaySettings::setZoomSetting(const JsonObject& parameters, JsonObject& response)
        {   //sample servicemanager response:
            MYTRACEMETHOD();
            string zoomSetting = parameters["zoomSetting"].String();
            returnIfParamNotFound(zoomSetting);
            bool success = true;
            try
            {
#ifdef USE_IARM
                zoomSetting = svc2iarm(zoomSetting);
#endif
                // TODO: why is this always the first one in the list? 
                device::VideoDevice &decoder = device::Host::getInstance().getVideoDevices().at(0);
                decoder.setDFC(zoomSetting);
            }
            catch(const device::Exception& err)
            {
                LOG_DEVICE_EXCEPTION1(zoomSetting);
                success = false;
            }
            returnResponse(success);
        }
        uint32_t DisplaySettings::getCurrentResolution(const JsonObject& parameters, JsonObject& response)
        {   //sample servicemanager response:{"success":true,"resolution":"720p"}
            MYTRACEMETHOD();
            string videoDisplay = parameters.HasLabel("videoDisplay") ? parameters["videoDisplay"].String() : "HDMI0";
            bool success = true;
            try
            {
                device::VideoOutputPort &vPort = device::Host::getInstance().getVideoOutputPort(videoDisplay);
                response["resolution"] = vPort.getResolution().getName();
            }
            catch(const device::Exception& err)
            {
                LOG_DEVICE_EXCEPTION1(videoDisplay);
                success = false;
            }
            returnResponse(success);
        }
        uint32_t DisplaySettings::setCurrentResolution(const JsonObject& parameters, JsonObject& response)
        {   //sample servicemanager response:
            MYTRACEMETHOD();
            string videoDisplay = parameters["videoDisplay"].String();
            string resolution = parameters["resolution"].String();
            returnIfParamNotFound(videoDisplay);
            returnIfParamNotFound(resolution);
            bool success = true;
            try
            {
                device::VideoOutputPort &vPort = device::Host::getInstance().getVideoOutputPort(videoDisplay);
                vPort.setResolution(resolution);
            }
            catch (const device::Exception& err)
            {
                LOG_DEVICE_EXCEPTION2(videoDisplay, resolution);
                success = false;
            }
            returnResponse(success);
        }
        uint32_t DisplaySettings::getSoundMode(const JsonObject& parameters, JsonObject& response)
        {   //sample servicemanager response:{"success":true,"soundMode":"AUTO (Dolby Digital 5.1)"}
            MYTRACEMETHOD();
            string videoDisplay = parameters["videoDisplay"].String();//empty value will browse all ports
            bool validPortName = true;

            if (getApiVersionNumber() < 5)
            {
                /* Convert videoDisplay to connected audio ports */
                if (videoDisplay.empty()) 
                {
                    /* Empty is allowed */
                }
                else if (stringContains(videoDisplay,"HDMI"))
                {
                    videoDisplay = "HDMI0";        
                }
                else if (stringContains(videoDisplay,"COMPONENT"))
                {
                    videoDisplay = "SPDIF0";        
                }
                else 
                {
                    validPortName = false;
                }
            }
            else 
            {
                /* From DS_5, the port specified must be AudioPort itself */
                if (videoDisplay.empty()) 
                {
                    /* Empty is allowed */
                }
                if (stringContains(videoDisplay,"HDMI"))
                {
                    videoDisplay = "HDMI0";        
                }
                else if (stringContains(videoDisplay,"SPDIF"))
                {
                    videoDisplay = "SPDIF0";        
                }
                else 
                {
                    validPortName = false;
                }
            }

            if (!validPortName) 
                videoDisplay = "HDMI0";

            string modeString("");
            device::AudioStereoMode mode = device::AudioStereoMode::kStereo;  //default to stereo

            try
            {
                /* Return the sound mode of the audio ouput connected to the specified videoDisplay */
                /* Check if HDMI is connected - Return (default) Stereo Mode if not connected */
                if (videoDisplay.empty()) 
                {
                    if (device::Host::getInstance().getVideoOutputPort("HDMI0").isDisplayConnected()) 
                    {
                        videoDisplay = "HDMI0";
                    }
                    else 
                    {
                        /*  * If HDMI is not connected  
                            * Get the SPDIF if it is supported by platform
                            * If Platform does not have connected ports. Default to HDMI.
                        */
                        videoDisplay = "HDMI0";    
                        device::List<device::VideoOutputPort> vPorts = device::Host::getInstance().getVideoOutputPorts();
                        for (size_t i = 0; i < vPorts.size(); i++) 
                        {
                            device::VideoOutputPort &vPort = vPorts.at(i);
                            if (vPort.isDisplayConnected())
                            {
                                videoDisplay = "SPDIF0";
                                break;
                            }
                        }
                    }
                }

                device::AudioOutputPort aPort = device::Host::getInstance().getAudioOutputPort(videoDisplay);

                if (aPort.isConnected()) 
                {
            	
                    mode = aPort.getStereoMode();

                    if ((getApiVersionNumber() >= 5) && (aPort.getType().getId() == device::AudioOutputPortType::kHDMI))
                    {
                        /* In DS5, "Surround" implies "Auto" */
                        if (aPort.getStereoAuto() || mode == device::AudioStereoMode::kSurround)
                        {
                            MYLOG("HDMI0 is in Auto Mode\r\n");
                            int surroundMode = device::Host::getInstance().getVideoOutputPort("HDMI0").getDisplay().getSurroundMode();
                            if ( surroundMode & dsSURROUNDMODE_DDPLUS)
                            {
                                MYLOG("getSoundMode: HDMI0 has surround DDPlus\r\n");
                                modeString.append("AUTO (Dolby Digital Plus)");
                            }
                            else if (surroundMode & dsSURROUNDMODE_DD)
                            {
                                MYLOG("getSoundMode: HDMI0 has surround DD 5.1\r\n");
                                modeString.append("AUTO (Dolby Digital 5.1)");
                            }
                            else 
                            {
                                MYLOG("getSoundMode: HDMI0 does not surround\r\n");
                                modeString.append("AUTO (Stereo)");
                            }
                        }
                        else
                        {
                            modeString.append(mode.toString());
                        }
                    }
                    else 
                    {
            	       if ((getApiVersionNumber() >= 5) && (mode == device::AudioStereoMode::kSurround))
                        {
                            modeString.append("Surround");
                        }
                        else 
                        {
                            modeString.append(mode.toString());
                        }
                    }
                }
                else
                {
                   /* 
                    * VideoDisplay is not connected. Its audio mode is unknown. Return
                    * "Stereo" as safe default;
                    */
                    mode = device::AudioStereoMode::kStereo;
                    if (getApiVersionNumber() >= 5) 
                    {
                        modeString.append("AUTO (Stereo)");
                    }
                    else 
                    {
                        modeString.append(mode.toString());
                    }
                }
            }
            catch (const device::Exception& err)
            {
                LOG_DEVICE_EXCEPTION0();
                // 
                // Exception
                // "Stereo" as safe default;
                //
                mode = device::AudioStereoMode::kStereo;
                if (getApiVersionNumber() >= 5) 
                {
                    modeString += "AUTO (Stereo)";
                }
                else 
                {
                    modeString += mode.toString();
                }
            }

            MYWARN("getSoundMode: display = %s, mode = %s!\n", videoDisplay.c_str(), modeString.c_str());
#ifdef USE_IARM
            modeString = iarm2svc(modeString);
#endif
            response["soundMode"] = modeString;
            returnResponse(true);
        }
        uint32_t DisplaySettings::setSoundMode(const JsonObject& parameters, JsonObject& response)
        {   //sample servicemanager response:
            MYTRACEMETHOD();
            string videoDisplay = parameters["videoDisplay"].String();//missing or empty string and we will set all ports
            string soundMode = parameters["soundMode"].String();
            returnIfParamNotFound(soundMode);
            bool success = true;
            device::AudioStereoMode mode = device::AudioStereoMode::kStereo;  //default to stereo
            bool stereoAuto = false;

            if (soundMode == "mono")
            {
                mode = device::AudioStereoMode::kMono;
            }
            else if (soundMode == "stereo")
            {
                mode = device::AudioStereoMode::kStereo;
            }
            else if (soundMode == "surround")
            {
                mode = device::AudioStereoMode::kSurround;
            }
            else if (soundMode == "passthru")
            {
                mode = device::AudioStereoMode::kPassThru;
            }
            else if ((getApiVersionNumber() >= 5) && ((soundMode == "auto") || (strncasecmp(soundMode.c_str(), "auto ", 5) == 0)))
            {
                /* 
                 * anthing after "auto" is only descriptive, and can be ignored.
                 * use kSurround in this case.
                 */
                if (videoDisplay.empty())
                    videoDisplay = "HDMI0";
                stereoAuto = true;
                mode = device::AudioStereoMode::kSurround;
            }
            else if ((getApiVersionNumber() >= 5) && (soundMode == "dolby digital 5.1"))
            {
                mode = device::AudioStereoMode::kSurround;
            }
            else 
            {
            }

            bool validPortName = true;

            if (getApiVersionNumber() < 5) {
                /* Convert videoDisplay to connected audio ports */
                if (videoDisplay.empty()) 
                {
                    /* Empty is allowed */
                }
                else if (stringContains(videoDisplay,"HDMI"))
                {
                    videoDisplay = "HDMI0";        
                }
                else if (stringContains(videoDisplay,"COMPONENT"))
                {
                    videoDisplay = "SPDIF0";        
                }
                else 
                {
                    validPortName = false;
                }
            }
            else 
            {
                /* From DS_5, the port specified must be AudioPort itself */
                if (videoDisplay.empty()) 
                {
                    /* Empty is allowed */
                }
                else if (stringContains(videoDisplay,"HDMI"))
                {
                    videoDisplay = "HDMI0";        
                }
                else if (stringContains(videoDisplay,"SPDIF"))
                {
                    videoDisplay = "SPDIF0";        
                }
                else 
                {
                    validPortName = false;
                }
            }

            if (!validPortName)
            { 
                MYERROR("setSoundMode has Invalid port Name : display = %s, mode = %s!\n", videoDisplay.c_str(), soundMode.c_str());
                returnResponse(false);
            }

            MYWARN("setSoundMode: display = %s, mode = %s!\n", videoDisplay.c_str(), soundMode.c_str());

            try
            {
                //now setting the sound mode for specified video display types
                if (!videoDisplay.empty()) 
                {
                    device::AudioOutputPort aPort = device::Host::getInstance().getAudioOutputPort(videoDisplay);
                    if (aPort.isConnected())
                    {
                        /* Auto mode is only for HDMI and DS5 and non-Passthru*/
                        if (getApiVersionNumber() >= 5 && aPort.getType().getId() == device::AudioOutputPortType::kHDMI && (!(mode == device::AudioStereoMode::kPassThru)))
                        {
                            aPort.setStereoAuto(stereoAuto);
                            if (stereoAuto) 
                            {
                                if (device::Host::getInstance().getVideoOutputPort("HDMI0").getDisplay().getSurroundMode())
                                {
                                    mode = device::AudioStereoMode::kSurround;
                                }
                                else 
                                {
                                    mode = device::AudioStereoMode::kStereo;
                                }
                            }
                        }
                        else if (aPort.getType().getId() == device::AudioOutputPortType::kHDMI) {
                            MYERROR("setSoundMode: reset auto on %s for mode = %s!\n", videoDisplay.c_str(), soundMode.c_str());
                            aPort.setStereoAuto(false);
                        }
                        //TODO: if mode has not changed, we can skip the extra call
                        aPort.setStereoMode(mode.toString());
                    }
                }
                else 
                {
                    /* No videoDisplay is specified, setMode to all connected ports */
                    JsonObject params;
                    params["videoDisplay"] = "HDMI0";
                    params["soundMode"] = soundMode;
                    JsonObject unusedResponse;
                    setSoundMode(params, response);
                    if (getApiVersionNumber() < 5)
                    {
                        params["videoDisplay"] = "COMPONENT";
                        setSoundMode(params, unusedResponse);
                    }
                    else
                    {
                        params["videoDisplay"] = "SPDIF0";
                        setSoundMode(params, unusedResponse);
                    }
                }
            }
            catch (const device::Exception& err)
            {
                LOG_DEVICE_EXCEPTION0();
                success = false;
            }
            //TODO(MROLLINS) -- so this is interesting.  ServiceManager had a settingChanged event that I guess handled settings from many services.
            //Does that mean we need to save our setting back to another plugin that would own settings (and this settingsChanged event) ?
            //ServiceManager::getInstance()->saveSetting(this, SETTING_DISPLAY_SERVICE_SOUND_MODE, soundMode);

            returnResponse(success);
        }
        uint32_t DisplaySettings::readEDID(const JsonObject& parameters, JsonObject& response)
        {   //sample servicemanager response: {"EDID":"AP///////wBSYgYCAQEBAQEXAQOAoFp4CvCdo1VJmyYPR0ovzgCBgIvAAQEBAQEBAQEBAQEBAjqAGHE4LUBYLEUAQIRjAAAeZiFQsFEAGzBAcDYAQIRjAAAeAAAA/ABUT1NISUJBLVRWCiAgAAAA/QAXSw9EDwAKICAgICAgAbECAytxSpABAgMEBQYHICImCQcHEQcYgwEAAGwDDAAQADgtwBUVHx/jBQMBAR2AGHEcFiBYLCUAQIRjAACeAR0AclHQHiBuKFUAQIRjAAAejArQiiDgLRAQPpYAsIRDAAAYjAqgFFHwFgAmfEMAsIRDAACYAAAAAAAAAAAAAAAA9w=="
            //sample this thunder plugin    : {"EDID":"AP///////wBSYgYCAQEBAQEXAQOAoFp4CvCdo1VJmyYPR0ovzgCBgIvAAQEBAQEBAQEBAQEBAjqAGHE4LUBYLEUAQIRjAAAeZiFQsFEAGzBAcDYAQIRjAAAeAAAA/ABUT1NISUJBLVRWCiAgAAAA/QAXSw9EDwAKICAgICAgAbECAytxSpABAgMEBQYHICImCQcHEQcYgwEAAGwDDAAQADgtwBUVHx/jBQMBAR2AGHEcFiBYLCUAQIRjAACeAR0AclHQHiBuKFUAQIRjAAAejArQiiDgLRAQPpYAsIRDAAAYjAqgFFHwFgAmfEMAsIRDAACYAAAAAAAAAAAAAAAA9w"}
            MYTRACEMETHOD();
            returnIfWrongApiVersion(4);
            std::vector<uint8_t> edidVec({'u','n','k','n','o','w','n' });
            try
            {
                std::vector<uint8_t> edidVec2;
                device::VideoOutputPort vPort = device::Host::getInstance().getVideoOutputPort("HDMI0");
                if (vPort.isDisplayConnected())
                {
                    vPort.getDisplay().getEDIDBytes(edidVec2);
                    edidVec = edidVec2;//edidVec must be "unknown" unless we successfully get to this line
                }
                else
                {
                    MYWARN("readEDID failure: HDMI0 not connected!\n");
                }
            }
            catch (const device::Exception& err)
            {
                LOG_DEVICE_EXCEPTION0();
            }
            //convert to base64
            uint16_t size = std::min(edidVec.size(), (size_t)std::numeric_limits<uint16_t>::max());
            if(edidVec.size() > (size_t)std::numeric_limits<uint16_t>::max())
                MYERROR("readEDID size too large to use ToString base64 wpe api\n");
            string edidbase64;
            Core::ToString((uint8_t*)&edidVec[0], size, false, edidbase64);
            response["EDID"] = edidbase64;
            returnResponse(true);
        }
        uint32_t DisplaySettings::readHostEDID(const JsonObject& parameters, JsonObject& response)
        {   //sample servicemanager response:
            MYTRACEMETHOD();
            returnIfWrongApiVersion(4);
            std::vector<uint8_t> edidVec({'u','n','k','n','o','w','n' });
            try
            {
                std::vector<unsigned char> edidVec2;
                device::Host::getInstance().getHostEDID(edidVec2);
                edidVec = edidVec2;//edidVec must be "unknown" unless we successfully get to this line                
                MYLOG("readHostEDID: getHostEDID size is %d.\n", int(edidVec2.size()));
            }
            catch (const device::Exception& err)
            {
                LOG_DEVICE_EXCEPTION0();
            }
            //convert to base64
            string base64String;
            uint16_t size = std::min(edidVec.size(), (size_t)std::numeric_limits<uint16_t>::max());
            if(edidVec.size() > (size_t)std::numeric_limits<uint16_t>::max())
                MYLOG("readHostEDID size too large to use ToString base64 wpe api\n");
            Core::ToString((uint8_t*)&edidVec[0], size, false, base64String);
            response["EDID"] = base64String;
            returnResponse(true);
        }
        uint32_t DisplaySettings::getActiveInput(const JsonObject& parameters, JsonObject& response)
        {   //sample servicemanager response:
            MYTRACEMETHOD();
            returnIfWrongApiVersion(5);
            string videoDisplay = parameters.HasLabel("videoDisplay") ? parameters["videoDisplay"].String() : "HDMI0";
            bool active = true;
            try
            {
                device::VideoOutputPort &vPort = device::Host::getInstance().getVideoOutputPort(videoDisplay);
                active = (vPort.isDisplayConnected() && vPort.isActive());
            }
            catch(const device::Exception& err)
            {
                LOG_DEVICE_EXCEPTION1(videoDisplay);
            }  
            response["activeInput"] = JsonValue(active);
            returnResponse(true);
        }
        uint32_t DisplaySettings::getTvHDRSupport(const JsonObject& parameters, JsonObject& response)
        {   //sample servicemanager response:{"standards":["none"],"supportsHDR":false}
            MYTRACEMETHOD();
            returnIfWrongApiVersion(6);
            
            JsonArray hdrCapabilities;
            int capabilities = dsHDRSTANDARD_NONE;

            try
            {
                device::VideoOutputPort vPort = device::VideoOutputPortConfig::getInstance().getPort("HDMI0");
                if (vPort.isDisplayConnected())
                    vPort.getTVHDRCapabilities(&capabilities);
            }
            catch(const device::Exception& err)
            {
                LOG_DEVICE_EXCEPTION0();
            }                

            if(!capabilities)hdrCapabilities.Add("none");
            if(capabilities & dsHDRSTANDARD_HDR10)hdrCapabilities.Add("HDR10");
            if(capabilities & dsHDRSTANDARD_DolbyVision)hdrCapabilities.Add("Dolby Vision");
            if(capabilities & dsHDRSTANDARD_TechnicolorPrime)hdrCapabilities.Add("Technicolor Prime");

            if(capabilities)
            {
                response["supportsHDR"] = true;
            }
            else
            {
                response["supportsHDR"] = false;
            }
            response["standards"] = hdrCapabilities;
            for (uint32_t i = 0; i < hdrCapabilities.Length(); i++)
            {
               MYLOG("getTvHDRSupport:%s\n", hdrCapabilities[i].String());
            }
            returnResponse(true);
        }
        uint32_t DisplaySettings::getSettopHDRSupport(const JsonObject& parameters, JsonObject& response)
        {   //sample servicemanager response:{"standards":["HDR10"],"supportsHDR":true}
            MYTRACEMETHOD();
            returnIfWrongApiVersion(6);
            JsonArray hdrCapabilities;
            int capabilities = dsHDRSTANDARD_NONE;

            try
            {
                device::VideoDevice &device = device::Host::getInstance().getVideoDevices().at(0);
                device.getHDRCapabilities(&capabilities);
            }
            catch(const device::Exception& err)
            {
                LOG_DEVICE_EXCEPTION0();
            } 
                        
            if(!capabilities)hdrCapabilities.Add("none");
            if(capabilities & dsHDRSTANDARD_HDR10)hdrCapabilities.Add("HDR10");
            if(capabilities & dsHDRSTANDARD_DolbyVision)hdrCapabilities.Add("Dolby Vision");
            if(capabilities & dsHDRSTANDARD_TechnicolorPrime)hdrCapabilities.Add("Technicolor Prime");

            if(capabilities)
            {
                response["supportsHDR"] = true;
            }
            else
            {
                response["supportsHDR"] = false;
            }
            response["standards"] = hdrCapabilities;
            for (uint32_t i = 0; i < hdrCapabilities.Length(); i++)
            {
               MYLOG("getSettopHDRSupport:%s\n", hdrCapabilities[i].String());
            }
            returnResponse(true);
        }
        uint32_t DisplaySettings::setVideoPortStatusInStandby(const JsonObject& parameters, JsonObject& response)
        {
            MYTRACEMETHOD();
            returnIfWrongApiVersion(7);
            string portname = parameters["portName"].String();
            returnIfParamNotFound(portname); 
            bool enabled = parameters["enabled"].Boolean();
            IARM_Bus_PWRMgr_StandbyVideoState_Param_t param;
            param.isEnabled = enabled;
            strncpy(param.port, portname.c_str(), PWRMGR_MAX_VIDEO_PORT_NAME_LENGTH);
            bool success = true;
            if(IARM_RESULT_SUCCESS != IARM_Bus_Call(IARM_BUS_PWRMGR_NAME, IARM_BUS_PWRMGR_API_SetStandbyVideoState, &param, sizeof(param)))
            {
                MYERROR("setVideoPortStatusInStandby failed. Port: %s. enable:%d\n", param.port, param.isEnabled);
                response["error_message"] = "Bus failure";
                success = false;
            }
            else if(0 != param.result)
            {
                MYERROR("setVideoPortStatusInStandby failed with result %d. Port: %s. enable:%d\n", param.result, param.port, param.isEnabled);
                response["error_message"] = "internal error";
                success = false;
            }
            returnResponse(success);
        }
        uint32_t DisplaySettings::getVideoPortStatusInStandby(const JsonObject& parameters, JsonObject& response)
        {
            MYTRACEMETHOD();
            returnIfWrongApiVersion(7);
            string portname = parameters["portName"].String();
            returnIfParamNotFound(portname);            
            bool success = true;
            IARM_Bus_PWRMgr_StandbyVideoState_Param_t param;
            strncpy(param.port, portname.c_str(), PWRMGR_MAX_VIDEO_PORT_NAME_LENGTH);
            if(IARM_RESULT_SUCCESS != IARM_Bus_Call(IARM_BUS_PWRMGR_NAME, IARM_BUS_PWRMGR_API_GetStandbyVideoState, &param, sizeof(param)))
            {
                MYERROR("getVideoPortStatusInStandby failed. Port: %s. enable:%d\n", param.port, param.isEnabled);
                response["error_message"] = "Bus failure";
                success = false;
            }
            else if(0 != param.result)
            {
                MYERROR("getVideoPortStatusInStandby failed with result %d. Port: %s. enable:%d\n", param.result, param.port, param.isEnabled);
                response["error_message"] = "internal error";
                success = false;
            }
            else
            {
                bool enabled(0 != param.isEnabled);
                MYLOG("video port is %s\n", enabled ? "enabled" : "disabled");
                response["videoPortStatusInStandby"] = enabled;
            }
            returnResponse(success);
        }
        //End methods
        //Begin events
        void DisplaySettings::resolutionPreChange()
        {
            MYTRACE();
            sendNotify("resolutionPreChange", JsonObject());
        }
        void DisplaySettings::resolutionChanged(int width, int height)
        {
            MYTRACE();
            vector<string> connectedDisplays;
            getConnectedVideoDisplaysHelper(connectedDisplays);
        
            string firstDisplay = "";
            string firstResolution = "";
            bool firstResolutionSet = false;
            for (int i = 0; i < (int)connectedDisplays.size(); i++)
            {
                string resolution;
                string display = connectedDisplays.at(i);
                try
                {
                    resolution = device::Host::getInstance().getVideoOutputPort(display).getResolution().getName();
                }
                catch(const device::Exception& err)
                {
                    LOG_DEVICE_EXCEPTION1(display);
                }
                if (!resolution.empty())
                {
                    if (stringContains(display,"HDMI"))
                    {
                        // only report first HDMI connected device is HDMI is connected
                        JsonObject params;
                        params["width"] = width;
                        params["height"] = height;
                        params["videoDisplayType"] = display;
                        params["resolution"] = resolution;
                        sendNotify("resolutionChanged", params);                        
                        return;
                    }
                    else if (!firstResolutionSet)
                    {
                        firstDisplay = display;
                        firstResolution = resolution;
                        firstResolutionSet = true;
                    }
                }
            }
            if (firstResolutionSet)
            {
                //if HDMI is not connected then notify the server of first connected device
                JsonObject params;
                params["width"] = width;
                params["height"] = height;
                params["videoDisplayType"] = firstDisplay;
                params["resolution"] = firstResolution;
                sendNotify("resolutionChanged", params);                        
            }
        }
        void DisplaySettings::zoomSettingUpdated(const string& zoomSetting)
        {//servicemanager sample: {"name":"zoomSettingUpdated","params":{"zoomSetting":"None","success":true,"videoDisplayType":"all"}
         //servicemanager sample: {"name":"zoomSettingUpdated","params":{"zoomSetting":"Full","success":true,"videoDisplayType":"all"}
            MYTRACE();
            JsonObject params;
            params["zoomSetting"] = zoomSetting;
            params["videoDisplayType"] = "all";
            sendNotify("zoomSettingUpdated", params);
        }
        void DisplaySettings::activeInputChanged(bool activeInput)
        {
            MYTRACE();
            if(getApiVersionNumber() < 5)
                return;
            JsonObject params;
            params["activeInput"] = activeInput;
            sendNotify("activeInputChanged", params);
        }
        void DisplaySettings::connectedVideoDisplaysUpdated(int hdmiHotPlugEvent)
        {
            MYTRACE();
            static int previousStatus = HDMI_HOT_PLUG_EVENT_CONNECTED; 
            static int firstTime = 1;

            if (firstTime || previousStatus != hdmiHotPlugEvent)
            {
                firstTime = 0;
                JsonArray connectedDisplays;
                if (HDMI_HOT_PLUG_EVENT_CONNECTED == hdmiHotPlugEvent)
                {
                    connectedDisplays.Add("HDMI0");
                }
                else
                {
                    /* notify Empty list on HDMI-output-disconnect hotplug */
                }

                JsonObject params;
                params["connectedVideoDisplays"] = connectedDisplays;
                sendNotify("connectedVideoDisplaysUpdated", params);
            }
            previousStatus = hdmiHotPlugEvent;
        }
        //End events
        
        void DisplaySettings::getConnectedVideoDisplaysHelper(std::vector<string>& connectedDisplays)
        {
            MYTRACE();
            try
            {
                device::List<device::VideoOutputPort> vPorts = device::Host::getInstance().getVideoOutputPorts();
                for (size_t i = 0; i < vPorts.size(); i++)
                {
                    device::VideoOutputPort &vPort = vPorts.at(i);
                    if (vPort.isDisplayConnected())
                    {
                        string displayName = vPort.getName();
                        if (strncasecmp(displayName.c_str(), "hdmi", 4)==0)
                        {
                            connectedDisplays.clear();
                            connectedDisplays.emplace_back(displayName);
                            break;
                        }
                        else
                        {
                            vectorSet(connectedDisplays, displayName);
                        }
                    }
                }
            }
            catch(const device::Exception& err)
            {
                LOG_DEVICE_EXCEPTION0();
            } 
        }
        uint32_t DisplaySettings::getApiVersionNumber()
        {
            return m_apiVersionNumber;
        }
        void DisplaySettings::setApiVersionNumber(unsigned int apiVersionNumber)
        {
            MYWARN("setApiVersionNumber enter version=%d", (int)apiVersionNumber);
            
            if (apiVersionNumber <= 4)
            {
              try
              {
                device::AudioOutputPort aPort = device::Host::getInstance().getAudioOutputPort("HDMI0");

                MYWARN("setApiVersionNumber aPort.getStereoAuto()=%d", (int)aPort.getStereoAuto());
                if (aPort.getStereoAuto()) 
                {
                    MYWARN(" setApiVersionNumber DS version check: AUTO is set, resetting");
                    aPort.setStereoAuto(false);
                    aPort.setStereoMode(device::AudioStereoMode::kSurround);
                }
                

                device::AudioStereoMode mode = aPort.getStereoMode(/*from persistent*/true);

                MYWARN("setApiVersionNumber kPassThru=%d", (int)(mode == device::AudioStereoMode::kPassThru));

                if (mode == device::AudioStereoMode::kPassThru) 
                {
                    MYWARN(" setApiVersionNumberDS version check: PASSTHRU is set, resetting");
                    aPort.setStereoAuto(false);
                    aPort.setStereoMode(device::AudioStereoMode::kSurround);
                    MYWARN("DS version 4 set with Audio Surround");
                }
              }
              catch (const device::Exception& err)
              {
                  LOG_DEVICE_EXCEPTION0();              
                  MYERROR(" setApiVersionNumber exception caught set surround, now try stereo");
                  try {
                      device::AudioOutputPort aPort = device::Host::getInstance().getAudioOutputPort("HDMI0");
                      aPort.setStereoAuto(false);
                      aPort.setStereoMode(device::AudioStereoMode::kStereo);
                      MYWARN("DS version 4 set with Audio stereo");
                   }
                  catch (const device::Exception& err) {
                      LOG_DEVICE_EXCEPTION0();
                      MYERROR("exception caught set stereo");
                  }
               }
            }
            m_apiVersionNumber = apiVersionNumber;
        }                                                    
	} // namespace Plugin
} // namespace WPEFramework
