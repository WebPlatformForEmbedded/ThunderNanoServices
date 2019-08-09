
#include "Module.h"
#include "Bluetooth.h"
#include <interfaces/json/JsonData_BluetoothControl.h>

/*
    // Copy the code below to Bluetooth class definition
    // Note: The Bluetooth class must inherit from PluginHost::JSONRPC

    private:
        void RegisterAll();
        void UnregisterAll();
        uint32_t endpoint_pair(const JsonData::BluetoothControl::PairParamsInfo& params);
        uint32_t endpoint_connect(const JsonData::BluetoothControl::PairParamsInfo& params);
        uint32_t endpoint_scan(const JsonData::BluetoothControl::ScanParamsData& params);
        uint32_t endpoint_stopscan();
        uint32_t endpoint_unpair(const JsonData::BluetoothControl::PairParamsInfo& params);
        uint32_t endpoint_disconnect(const JsonData::BluetoothControl::DisconnectParamsData& params);
        uint32_t get_scanning(Core::JSON::Boolean& response) const;
        uint32_t get_device(const string& index, Core::JSON::ArrayType<JsonData::BluetoothControl::DeviceData>& response) const;
*/

namespace WPEFramework {

namespace Plugin {

    using namespace JsonData::Bluetooth;

    // Registration
    //

    void BluetoothControl::RegisterAll()
    {
        Register<PairParamsInfo,void>(_T("pair"), &BluetoothControl::endpoint_pair, this);
        Register<PairParamsInfo,void>(_T("connect"), &BluetoothControl::endpoint_connect, this);
        Register<ScanParamsData,void>(_T("scan"), &BluetoothControl::endpoint_scan, this);
        Register<void,void>(_T("stopscan"), &BluetoothControl::endpoint_stopscan, this);
        Register<PairParamsInfo,void>(_T("unpair"), &BluetoothControl::endpoint_unpair, this);
        Register<DisconnectParamsData,void>(_T("disconnect"), &BluetoothControl::endpoint_disconnect, this);
        Property<Core::JSON::Boolean>(_T("scanning"), &BluetoothControl::get_scanning, nullptr, this);
        Property<Core::JSON::ArrayType<DeviceData>>(_T("device"), &BluetoothControl::get_device, nullptr, this);
    }

    void BluetoothControl::UnregisterAll()
    {
        Unregister(_T("disconnect"));
        Unregister(_T("unpair"));
        Unregister(_T("stopscan"));
        Unregister(_T("scan"));
        Unregister(_T("connect"));
        Unregister(_T("pair"));
        Unregister(_T("device"));
        Unregister(_T("scanning"));
    }

    // API implementation
    //

    // Method: pair - Pair host with bluetooth device
    // Return codes:
    //  - ERROR_NONE: Success
    //  - ERROR_UNKNOWN_KEY: Device not found
    //  - ERROR_GENERAL: Failed to pair
    //  - ERROR_ASYNC_ABORTED: Pairing aborted
    uint32_t BluetoothControl::endpoint_pair(const PairParamsInfo& params)
    {
        const string& device = params.Device.Value();

        DeviceImpl* device = Find(destination);
        if (device == nullptr) 
            return Core::ERROR_UNKNOWN_KEY;

        return device->Pair();
    }

    // Method: connect - Connect with bluetooth device
    // Return codes:
    //  - ERROR_NONE: Success
    //  - ERROR_UNKNOWN_KEY: Device not found
    //  - ERROR_GENERAL: Failed to connect
    //  - ERROR_ASYNC_ABORTED: Connecting aborted
    uint32_t BluetoothControl::endpoint_connect(const PairParamsInfo& params)
    {
        const string& device = params.Device.Value();

        DeviceImpl* device = Find(destination);
        if (device == nullptr) 
            return Core::ERROR_UNKNOWN_KEY;

        return device->Connect();
    }

    // Method: scan - Scan environment for bluetooth devices
    // Return codes:
    //  - ERROR_NONE: Success
    uint32_t BluetoothControl::endpoint_scan(const ScanParamsData& params)
    {
        uint32_t result = Core::ERROR_GENERAL;
        const bool& lowenergy = params.Lowenergy.Value();
        const bool& limited = params.Limited.Value();
        const bool& passive = params.Passive.Value();
        const uint32_t& duration = params.Duration.Value();

        uint8_t flags = 0;
        uint32_t type = 0x338B9E;

        if (lowenergy == true) {
            if (_application.Scan(duration, limited, passive) == true) {
                result = Core::ERROR_NONE;
            }
        } else {
            if (_application.Scan(duration, type, flags) == true) {
                result = Core::ERROR_NONE;
            }
        }

        return result;
    }

    // Method: stopscan - Connect with bluetooth device
    // Return codes:
    //  - ERROR_NONE: Success
    uint32_t BluetoothControl::endpoint_stopscan()
    {
        _application.Abort();

        return Core::ERROR_NONE;
    }

    // Method: unpair - Unpair host from a bluetooth device
    // Return codes:
    //  - ERROR_NONE: Success
    //  - ERROR_UNKNOWN_KEY: Device not found
    uint32_t BluetoothControl::endpoint_unpair(const PairParamsInfo& params)
    {
        uint32_t result = Core::ERROR_NONE;
        const string& device = params.Device.Value();

        DeviceImpl* device = Find(address);
        if (device == nullptr) 
            return Core::ERROR_UNKNOWN_KEY;

        return device->Unpair();
    }

    // Method: disconnect - Disconnects host from bluetooth device
    // Return codes:
    //  - ERROR_NONE: Success
    //  - ERROR_UNKNOWN_KEY: Device not found
    uint32_t BluetoothControl::endpoint_disconnect(const DisconnectParamsData& params)
    {
        uint32_t result = Core::ERROR_NONE;
        const string& device = params.Device.Value();
        const uint32_t& reason = params.Reason.Value();

        DeviceImpl* device = Find(address);
        if (device == nullptr) 
            return Core::ERROR_UNKNOWN_KEY;

        return device->Disconnect(reason);

        return result;
    }

    // Property: scanning - Tells if host is currently scanning for bluetooth devices
    // Return codes:
    //  - ERROR_NONE: Success
    uint32_t BluetoothControl::get_scanning(Core::JSON::Boolean& response) const
    {
        response = IsScanning();

        return Core::ERROR_NONE;
    }

    // Property: device - Informations about devices found during scanning
    // Return codes:
    //  - ERROR_NONE: Success
    //  - ERROR_UNKNOWN_KEY: Device not found
    uint32_t BluetoothControl::get_device(const string& index, Core::JSON::ArrayType<DeviceData>& response) const
    {
        uint32_t result = Core::ERROR_NONE;

        if (index.empty() == true) {
            for (auto device : _devices) {
                response.Add().Set(device);
                loop++;
            }
        } else {
            DeviceImpl* device = Find(index);

            if (device != nullptr) 
                response.Add().Set(device);
            else 
                result = Core::ERROR_UNKNOWN_KEY;
        }

        return result;
    }

} // namespace Plugin

}
