#include "provider_server.hpp"
#include "provider_panel.hpp"

#include <obs-module.h>
#include <obs-frontend-api.h>

#include <QDockWidget>
#include <QWidget>

#include <memory>
#include <exception>
#include <string>

OBS_DECLARE_MODULE()
OBS_MODULE_USE_DEFAULT_LOCALE("donationalerts-obs-provider", "en-US")

namespace {

std::unique_ptr<ProviderServer> provider;
constexpr char kDockId[] = "donationalertsProviderDock";
bool dock_registered = false;

void open_provider_panel(void *)
{
	auto *main_window = static_cast<QWidget *>(obs_frontend_get_main_window());
	if (!main_window)
		return;
	auto *dock = main_window->findChild<QDockWidget *>(QString::fromLatin1(kDockId));
	if (dock) {
		dock->show();
		dock->raise();
	}
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

		auto *panel = new ProviderPanel(instance->admin_token());
		if (!obs_frontend_add_dock_by_id(kDockId, obs_module_text("Panel.Title"), panel)) {
			delete panel;
			instance->stop();
			blog(LOG_ERROR, "[DonationAlerts Provider] Could not register the OBS dock.");
			return false;
		}
		dock_registered = true;
		provider = std::move(instance);
		blog(LOG_INFO, "[DonationAlerts Provider] Local API listening on 127.0.0.1:4041; OBS dock registered.");
		blog(LOG_INFO, "[DonationAlerts Provider] DonationAlerts OAuth is not configured yet.");
		obs_frontend_add_tools_menu_item(obs_module_text("Menu.OpenPanel"), open_provider_panel, nullptr);
		return true;
	} catch (const std::exception &error) {
		blog(LOG_ERROR, "[DonationAlerts Provider] Failed to start: %s", error.what());
		return false;
	}
}

void obs_module_unload(void)
{
	if (dock_registered) {
		obs_frontend_remove_dock(kDockId);
		dock_registered = false;
	}
	if (provider) {
		provider->stop();
		provider.reset();
	}
	blog(LOG_INFO, "[DonationAlerts Provider] Stopped.");
}
