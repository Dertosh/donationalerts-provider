#include "provider_server.hpp"
#include "provider_panel.hpp"

#include <obs-module.h>
#include <obs-frontend-api.h>

#include <QPointer>
#include <QWidget>

#include <memory>
#include <exception>
#include <string>

OBS_DECLARE_MODULE()
OBS_MODULE_USE_DEFAULT_LOCALE("donationalerts-obs-provider", "en-US")

namespace {

std::unique_ptr<ProviderServer> provider;
QPointer<ProviderPanel> panel;

void open_provider_panel(void *)
{
	if (!panel)
		return;
	panel->show();
	panel->raise();
	panel->activateWindow();
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

		auto *main_window = static_cast<QWidget *>(obs_frontend_get_main_window());
		if (!main_window) {
			instance->stop();
			blog(LOG_ERROR, "[DonationAlerts Provider] Could not get the OBS main window.");
			return false;
		}
		panel = new ProviderPanel(instance->admin_token());
		panel->setParent(main_window, Qt::Window);
		panel->hide();
		provider = std::move(instance);
		blog(LOG_INFO, "[DonationAlerts Provider] Local API listening on 127.0.0.1:4041; settings window registered.");
		obs_frontend_add_tools_menu_item(obs_module_text("Menu.OpenPanel"), open_provider_panel, nullptr);
		return true;
	} catch (const std::exception &error) {
		blog(LOG_ERROR, "[DonationAlerts Provider] Failed to start: %s", error.what());
		return false;
	}
}

void obs_module_unload(void)
{
	delete panel.data();
	panel = nullptr;
	if (provider) {
		provider->stop();
		provider.reset();
	}
	blog(LOG_INFO, "[DonationAlerts Provider] Stopped.");
}
