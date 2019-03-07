#include "DisplaySettings.h"

namespace WPEFramework {

	namespace Plugin {

		SERVICE_REGISTRATION(DisplaySettings, 1, 0);

		DisplaySettings::DisplaySettings()
			: PluginHost::JSONRPC()
			, _job(Core::ProxyType<PeriodicSync>::Create(this))
		{
			// PluginHost::JSONRPC method to register a JSONRPC method invocation for the method "time".
			Register<string, string>(_T("time"), &DisplaySettings::time, this);
		}

		/* virtual */ DisplaySettings::~DisplaySettings()
		{
			// PluginHost::JSONRPC method to unregister a JSONRPC method invocation for the method "time".
			Unregister(_T("time"));
		}

		/* virtual */ const string DisplaySettings::Initialize(PluginHost::IShell* /* service */)
		{
			_job->Period(5);
			PluginHost::WorkerPool::Instance().Schedule(Core::Time::Now().Add(5000), _job);

			// On success return empty, to indicate there is no error text.
			return (string());
		}

		/* virtual */ void DisplaySettings::Deinitialize(PluginHost::IShell* /* service */)
		{
			_job->Period(0);
			PluginHost::WorkerPool::Instance().Revoke(_job);
		}

		/* virtual */ string DisplaySettings::Information() const
		{
			// No additional info to report.
			return (string());
		}

		void DisplaySettings::SendTime() {
			// PluginHost::JSONRPC method to send out a JSONRPC message to all subscribers to the event "clock".
			Notify(_T("clock"), Core::JSON::String(Core::Time::Now().ToRFC1123()));
		}

	} // namespace Plugin

} // namespace WPEFramework
