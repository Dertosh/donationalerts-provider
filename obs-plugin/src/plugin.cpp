#include "provider_server.hpp"

#include <obs-module.h>
#include <obs-frontend-api.h>

#include <windows.h>
#include <shellapi.h>

#include <memory>
#include <exception>
#include <string>

OBS_DECLARE_MODULE()
OBS_MODULE_USE_DEFAULT_LOCALE("donationalerts-obs-provider", "en-US")

namespace {

std::unique_ptr<ProviderServer> provider;

void open_admin_panel(void *)
{
	const auto result = reinterpret_cast<std::intptr_t>(
		ShellExecuteW(nullptr, L"open", L"http://127.0.0.1:4041/admin", nullptr, nullptr, SW_SHOWNORMAL));
	if (result <= 32)
		blog(LOG_ERROR, "[DonationAlerts Provider] Could not open the admin page (ShellExecute error %lld).",
		     static_cast<long long>(result));
}

} // namespace

bool obs_module_load(void)
{
	try {
		auto instance = std::make_unique<ProviderServer>();
		std::string error;
		if (!instance->start(error)) {
			blog(LOG_ERROR, "[DonationAlerts Provider] %s", error.c_str());
			return false;
		}

		blog(LOG_INFO, "[DonationAlerts Provider] Local admin page: http://127.0.0.1:4041/admin");
		blog(LOG_WARNING, "[DonationAlerts Provider] Admin token (keep private): %s", instance->admin_token().c_str());
		blog(LOG_INFO, "[DonationAlerts Provider] Listening on localhost only; DonationAlerts OAuth is not configured yet.");

		provider = std::move(instance);
		obs_frontend_add_tools_menu_item("Open DonationAlerts Provider", open_admin_panel, nullptr);
		return true;
	} catch (const std::exception &error) {
		blog(LOG_ERROR, "[DonationAlerts Provider] Failed to start: %s", error.what());
		return false;
	}
}

void obs_module_unload(void)
{
	if (provider) {
		provider->stop();
		provider.reset();
	}
	blog(LOG_INFO, "[DonationAlerts Provider] Stopped.");
}
