#include "provider_panel.hpp"
#include "donation_stream.hpp"

#include <obs-module.h>

#include <windows.h>
#include <wincrypt.h>

#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QCoreApplication>
#include <QDateTime>
#include <QDateEdit>
#include <QMetaObject>
#include <QPointer>
#include <QDesktopServices>
#include <QDialog>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QLocale>
#include <QListWidget>
#include <QListWidgetItem>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QRandomGenerator>
#include <QSaveFile>
#include <QStringList>
#include <QTimer>
#include <QUrl>
#include <QUrlQuery>
#include <QVBoxLayout>

#include <cstdint>
#include <iterator>
#include <utility>

namespace {

QString localized(const char *key)
{
	return QString::fromUtf8(obs_module_text(key));
}

QUrl provider_url(const QString &path)
{
	return QUrl(QStringLiteral("http://127.0.0.1:4041") + path);
}

QNetworkRequest admin_request(const QString &path, const std::string &admin_token)
{
	QNetworkRequest request(provider_url(path));
	request.setRawHeader("X-Admin-Token", QByteArray::fromStdString(admin_token));
	return request;
}

QString response_error(const QByteArray &body, const QString &fallback)
{
	const auto document = QJsonDocument::fromJson(body);
	if (document.isObject()) {
		const auto object = document.object();
		QString message = object.value(QStringLiteral("error")).toString();
		if (message.isEmpty())
			message = object.value(QStringLiteral("error_description")).toString();
		if (message.isEmpty())
			message = object.value(QStringLiteral("message")).toString();
		if (!message.isEmpty())
			return message;
	}
	return fallback;
}

QString credential_path()
{
	return QDir(qEnvironmentVariable("APPDATA"))
		.filePath(QStringLiteral("obs-studio/plugin_config/donationalerts-obs-provider.dat"));
}

QByteArray protect_data(const QByteArray &plain)
{
	DATA_BLOB input{static_cast<DWORD>(plain.size()),
			reinterpret_cast<BYTE *>(const_cast<char *>(plain.constData()))};
	DATA_BLOB output{};
	if (!CryptProtectData(&input, L"DonationAlerts OBS Provider", nullptr, nullptr, nullptr,
			      CRYPTPROTECT_UI_FORBIDDEN, &output))
		return {};
	const QByteArray encrypted(reinterpret_cast<const char *>(output.pbData), static_cast<qsizetype>(output.cbData));
	LocalFree(output.pbData);
	return encrypted;
}

QByteArray unprotect_data(const QByteArray &encrypted)
{
	DATA_BLOB input{static_cast<DWORD>(encrypted.size()),
			reinterpret_cast<BYTE *>(const_cast<char *>(encrypted.constData()))};
	DATA_BLOB output{};
	if (!CryptUnprotectData(&input, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &output))
		return {};
	const QByteArray plain(reinterpret_cast<const char *>(output.pbData), static_cast<qsizetype>(output.cbData));
	LocalFree(output.pbData);
	return plain;
}

QString api_url(const QString &path)
{
	return QStringLiteral("https://www.donationalerts.com") + path;
}

void add_plugin_qt_library_path()
{
	HMODULE module = nullptr;
	if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
				reinterpret_cast<LPCWSTR>(&add_plugin_qt_library_path), &module))
		return;

	wchar_t module_path[MAX_PATH]{};
	const DWORD length = GetModuleFileNameW(module, module_path, static_cast<DWORD>(std::size(module_path)));
	if (length == 0 || length >= std::size(module_path))
		return;

	const auto plugin_directory = QFileInfo(QString::fromWCharArray(module_path, static_cast<qsizetype>(length)))
					     .absolutePath();
	const auto qt_plugin_path = QDir(plugin_directory).filePath(QStringLiteral("qt-plugins"));
	if (QDir(qt_plugin_path).exists())
		QCoreApplication::addLibraryPath(qt_plugin_path);
}

} // namespace

ProviderPanel::ProviderPanel(std::string admin_token)
	: admin_token_(std::move(admin_token)),
	  network_(new QNetworkAccessManager(this)),
	  status_(new QLabel(this)),
	  copy_status_button_(new QPushButton(localized("Panel.CopyStatus"), this)),
	  name_(new QLineEdit(QStringLiteral("obs-widget"), this)),
	  no_expiration_(new QCheckBox(localized("Panel.NoExpiration"), this)),
	  expiration_date_(new QDateEdit(this)),
	  donation_scope_(new QCheckBox(localized("Panel.Scope.Donations"), this)),
	  goal_scope_(new QCheckBox(localized("Panel.Scope.Goals"), this)),
	  poll_scope_(new QCheckBox(localized("Panel.Scope.Polls"), this)),
	  tokens_(new QListWidget(this)),
	  client_id_(new QLineEdit(this)),
	  client_secret_(new QLineEdit(this)),
	  issue_button_(new QPushButton(localized("Panel.IssueToken"), this)),
	  refresh_button_(new QPushButton(localized("Panel.RefreshTokens"), this)),
	  revoke_button_(new QPushButton(localized("Panel.RevokeToken"), this)),
	  connect_button_(new QPushButton(localized("OAuth.Connect"), this)),
	  disconnect_button_(new QPushButton(localized("OAuth.Disconnect"), this)),
	  debug_enabled_(new QCheckBox(localized("Debug.Enable"), this)),
	  debug_output_(new QPlainTextEdit(this)),
	  callback_timer_(new QTimer(this)),
	  donations_timer_(new QTimer(this))
{
	add_plugin_qt_library_path();
	setMinimumWidth(360);
	setWindowTitle(localized("Panel.Title"));
	auto *layout = new QVBoxLayout(this);
	auto *intro = new QLabel(
		localized("Panel.Intro"),
		this);
	intro->setWordWrap(true);
	layout->addWidget(intro);

	auto *oauth_group = new QGroupBox(localized("OAuth.Title"), this);
	auto *oauth_layout = new QVBoxLayout(oauth_group);
	auto *oauth_form = new QFormLayout;
	client_id_->setPlaceholderText(localized("OAuth.ClientId"));
	client_secret_->setPlaceholderText(localized("OAuth.ClientSecret"));
	client_secret_->setEchoMode(QLineEdit::Password);
	oauth_form->addRow(localized("OAuth.ClientId"), client_id_);
	oauth_form->addRow(localized("OAuth.ClientSecret"), client_secret_);
	oauth_layout->addLayout(oauth_form);
	auto *callback_hint = new QLabel(
		localized("OAuth.Callback").arg(QStringLiteral("http://127.0.0.1:4041/oauth/callback")), oauth_group);
	callback_hint->setWordWrap(true);
	oauth_layout->addWidget(callback_hint);
	auto *oauth_buttons = new QHBoxLayout;
	oauth_buttons->addWidget(connect_button_);
	oauth_buttons->addWidget(disconnect_button_);
	oauth_layout->addLayout(oauth_buttons);
	layout->addWidget(oauth_group);

	auto *form = new QFormLayout;
	name_->setMaxLength(80);
	expiration_date_->setCalendarPopup(true);
	expiration_date_->setMinimumDate(QDate::currentDate());
	expiration_date_->setMaximumDate(QDate(9999, 12, 30));
	expiration_date_->setDate(QDate::currentDate().addYears(1));
	expiration_date_->setDisplayFormat(QLocale().dateFormat(QLocale::ShortFormat));
	form->addRow(localized("Panel.TokenName"), name_);
	no_expiration_->setChecked(true);
	form->addRow(no_expiration_);
	form->addRow(localized("Panel.TokenLifetime"), expiration_date_);
	layout->addLayout(form);
	expiration_date_->setEnabled(false);
	connect(no_expiration_, &QCheckBox::toggled, expiration_date_, &QWidget::setDisabled);

	donation_scope_->setChecked(true);
	goal_scope_->setEnabled(false);
	poll_scope_->setEnabled(false);
	layout->addWidget(donation_scope_);
	layout->addWidget(goal_scope_);
	layout->addWidget(poll_scope_);

	auto *buttons = new QHBoxLayout;
	buttons->addWidget(issue_button_);
	buttons->addWidget(refresh_button_);
	layout->addLayout(buttons);
	layout->addWidget(new QLabel(localized("Panel.ActiveTokens"), this));
	layout->addWidget(tokens_, 1);
	layout->addWidget(revoke_button_);
	status_->setWordWrap(true);
	status_->setTextInteractionFlags(Qt::TextSelectableByMouse | Qt::TextSelectableByKeyboard);
	layout->addWidget(status_);
	layout->addWidget(copy_status_button_);
	debug_enabled_->setToolTip(localized("Debug.Warning"));
	layout->addWidget(debug_enabled_);
	debug_output_->setReadOnly(true);
	debug_output_->setMaximumBlockCount(300);
	debug_output_->setMaximumHeight(220);
	debug_output_->setPlaceholderText(localized("Debug.Empty"));
	debug_output_->hide();
	layout->addWidget(debug_output_);

	revoke_button_->setEnabled(false);
	connect(copy_status_button_, &QPushButton::clicked, this, [this] {
		QApplication::clipboard()->setText(status_->text());
	});
	connect(debug_enabled_, &QCheckBox::toggled, this, [this](bool enabled) {
		debug_output_->setVisible(enabled);
	});
	connect(issue_button_, &QPushButton::clicked, this, [this] { issue_token(); });
	connect(refresh_button_, &QPushButton::clicked, this, [this] { refresh_tokens(); });
	connect(revoke_button_, &QPushButton::clicked, this, [this] { revoke_selected_token(); });
	connect(connect_button_, &QPushButton::clicked, this, [this] { connect_donationalerts(); });
	connect(disconnect_button_, &QPushButton::clicked, this, [this] {
		callback_timer_->stop();
		donations_timer_->stop();
		if (donation_stream_)
			donation_stream_->stop();
		access_token_.clear();
		refresh_token_.clear();
		access_token_expires_at_ = 0;
		oauth_flow_active_ = false;
		publish_proxy_access_token(QString{});
		QFile::remove(credential_path());
		update_oauth_buttons();
		status_->setText(localized("OAuth.Disconnected"));
		publish_realtime_status(false, localized("OAuth.Disconnected"));
		publish_profile(QJsonObject{}, false);
		publish_donations(QJsonArray{});
	});
	connect(tokens_, &QListWidget::itemSelectionChanged, this, [this] {
		revoke_button_->setEnabled(tokens_->currentItem() != nullptr);
	});
	connect(callback_timer_, &QTimer::timeout, this, [this] { poll_oauth_callback(); });
	connect(donations_timer_, &QTimer::timeout, this, [this] { poll_donations(); });

	donation_stream_ = std::make_unique<DonationStream>();
	load_credentials();
	update_oauth_buttons();
	refresh_tokens();
	QTimer::singleShot(0, this, [this] { restore_saved_connection(); });
}

ProviderPanel::~ProviderPanel()
{
	if (donation_stream_)
		donation_stream_->stop();
}

void ProviderPanel::set_busy(bool busy)
{
	issue_button_->setEnabled(!busy);
	refresh_button_->setEnabled(!busy);
	revoke_button_->setEnabled(!busy && tokens_->currentItem() != nullptr);
}

void ProviderPanel::update_oauth_buttons()
{
	const bool has_credentials = !access_token_.isEmpty() || !refresh_token_.isEmpty();
	connect_button_->setEnabled(!has_credentials && !oauth_flow_active_);
	disconnect_button_->setEnabled(has_credentials && !oauth_flow_active_);
}

void ProviderPanel::connect_donationalerts()
{
	const QString client_id = client_id_->text().trimmed();
	if (client_id.isEmpty() || client_secret_->text().isEmpty()) {
		status_->setText(localized("OAuth.MissingCredentials"));
		return;
	}
	for (const QChar character : client_id) {
		if (!character.isDigit()) {
			status_->setText(localized("OAuth.InvalidClientId"));
			return;
		}
	}

	if (!save_credentials())
		return;

	oauth_flow_active_ = true;
	update_oauth_buttons();
	callback_timer_->stop();
	oauth_state_.clear();
	for (int index = 0; index < 4; ++index)
		oauth_state_ += QStringLiteral("%1").arg(QRandomGenerator::system()->generate(), 8, 16, QLatin1Char('0'));

	QUrl authorization(api_url(QStringLiteral("/oauth/authorize")));
	QUrlQuery query;
	query.addQueryItem(QStringLiteral("client_id"), client_id);
	query.addQueryItem(QStringLiteral("redirect_uri"), QStringLiteral("http://127.0.0.1:4041/oauth/callback"));
	query.addQueryItem(QStringLiteral("response_type"), QStringLiteral("code"));
	query.addQueryItem(QStringLiteral("scope"),
			   QStringLiteral("oauth-user-show oauth-donation-index oauth-donation-subscribe "
					  "oauth-goal-subscribe oauth-poll-subscribe"));
	query.addQueryItem(QStringLiteral("state"), oauth_state_);
	authorization.setQuery(query);
	if (!QDesktopServices::openUrl(authorization)) {
		oauth_flow_active_ = false;
		update_oauth_buttons();
		status_->setText(localized("OAuth.OpenBrowserFailed"));
		return;
	}

	status_->setText(localized("OAuth.Waiting"));
	callback_timer_->start(1000);
}

void ProviderPanel::poll_oauth_callback()
{
	auto *reply = network_->get(admin_request(QStringLiteral("/api/oauth/callback-code"), admin_token_));
	connect(reply, &QNetworkReply::finished, this, [this, reply] {
		const QByteArray body = reply->readAll();
		const auto network_error = reply->error();
		reply->deleteLater();
		if (network_error != QNetworkReply::NoError)
			return;

		QJsonParseError parse_error{};
		const auto document = QJsonDocument::fromJson(body, &parse_error);
		if (parse_error.error != QJsonParseError::NoError || !document.isObject())
			return;
		const auto callback = document.object();
		const QString error = callback.value(QStringLiteral("error")).toString();
		const QString code = callback.value(QStringLiteral("code")).toString();
		if (!error.isEmpty()) {
			callback_timer_->stop();
			oauth_flow_active_ = false;
			update_oauth_buttons();
			status_->setText(localized("OAuth.AuthorizationFailed").arg(error));
			return;
		}
		if (code.isEmpty())
			return;
		callback_timer_->stop();
		if (callback.value(QStringLiteral("state")).toString() != oauth_state_) {
			oauth_flow_active_ = false;
			update_oauth_buttons();
			status_->setText(localized("OAuth.StateMismatch"));
			return;
		}
		exchange_oauth_code(code);
	});
}

void ProviderPanel::exchange_oauth_code(const QString &code)
{
	QUrlQuery form;
	form.addQueryItem(QStringLiteral("grant_type"), QStringLiteral("authorization_code"));
	form.addQueryItem(QStringLiteral("client_id"), client_id_->text().trimmed());
	form.addQueryItem(QStringLiteral("client_secret"), client_secret_->text());
	form.addQueryItem(QStringLiteral("redirect_uri"), QStringLiteral("http://127.0.0.1:4041/oauth/callback"));
	form.addQueryItem(QStringLiteral("code"), code);

	QNetworkRequest request(QUrl(api_url(QStringLiteral("/oauth/token"))));
	request.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/x-www-form-urlencoded"));
	status_->setText(localized("OAuth.ExchangingCode"));
	auto *reply = network_->post(request, form.query(QUrl::FullyEncoded).toUtf8());
	connect(reply, &QNetworkReply::finished, this, [this, reply] {
		const QByteArray body = reply->readAll();
		const auto network_error = reply->error();
		const QString error_text = reply->errorString();
		reply->deleteLater();
		if (network_error != QNetworkReply::NoError) {
			oauth_flow_active_ = false;
			update_oauth_buttons();
			status_->setText(response_error(body, localized("OAuth.ExchangeFailed").arg(error_text)));
			return;
		}

		QJsonParseError parse_error{};
		const auto document = QJsonDocument::fromJson(body, &parse_error);
		const auto object = document.object();
		const QString access_token = object.value(QStringLiteral("access_token")).toString();
		if (parse_error.error != QJsonParseError::NoError || access_token.isEmpty()) {
			oauth_flow_active_ = false;
			update_oauth_buttons();
			status_->setText(response_error(body, localized("OAuth.InvalidTokenResponse")));
			return;
		}
		access_token_ = access_token;
		refresh_token_ = object.value(QStringLiteral("refresh_token")).toString();
		access_token_expires_at_ = QDateTime::currentSecsSinceEpoch() +
					   object.value(QStringLiteral("expires_in")).toInteger(3600);
		oauth_flow_active_ = false;
		update_oauth_buttons();
		const bool saved = save_credentials();
		publish_proxy_access_token(access_token_);
		donations_timer_->start(5000);
		if (saved)
			status_->setText(localized("OAuth.Connected"));
		fetch_profile();
		poll_donations();
	});
}

void ProviderPanel::refresh_access_token()
{
	if (token_refresh_in_flight_)
		return;
	if (refresh_token_.isEmpty()) {
		const QString message = localized("OAuth.NoRefreshToken");
		status_->setText(message);
		blog(LOG_WARNING, "[DonationAlerts Provider] Automatic connection cannot refresh the OAuth token.");
		publish_realtime_status(false, message);
		return;
	}
	token_refresh_in_flight_ = true;
	QUrlQuery form;
	form.addQueryItem(QStringLiteral("grant_type"), QStringLiteral("refresh_token"));
	form.addQueryItem(QStringLiteral("refresh_token"), refresh_token_);
	form.addQueryItem(QStringLiteral("client_id"), client_id_->text().trimmed());
	form.addQueryItem(QStringLiteral("client_secret"), client_secret_->text());
	form.addQueryItem(QStringLiteral("scope"),
			  QStringLiteral("oauth-user-show oauth-donation-index oauth-donation-subscribe "
					 "oauth-goal-subscribe oauth-poll-subscribe"));

	QNetworkRequest request(QUrl(api_url(QStringLiteral("/oauth/token"))));
	request.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/x-www-form-urlencoded"));
	auto *reply = network_->post(request, form.query(QUrl::FullyEncoded).toUtf8());
	connect(reply, &QNetworkReply::finished, this, [this, reply] {
		const QByteArray body = reply->readAll();
		const auto network_error = reply->error();
		const QString error_text = reply->errorString();
		reply->deleteLater();
		token_refresh_in_flight_ = false;
		if (network_error != QNetworkReply::NoError) {
			const QString message = response_error(body, localized("OAuth.RefreshFailed").arg(error_text));
			status_->setText(message);
			blog(LOG_WARNING, "[DonationAlerts Provider] OAuth token refresh failed: %s",
			     message.toUtf8().constData());
			publish_realtime_status(false, message);
			return;
		}

		QJsonParseError parse_error{};
		const auto document = QJsonDocument::fromJson(body, &parse_error);
		const auto object = document.object();
		const QString access_token = object.value(QStringLiteral("access_token")).toString();
		if (parse_error.error != QJsonParseError::NoError || access_token.isEmpty()) {
			const QString message = response_error(body, localized("OAuth.InvalidTokenResponse"));
			status_->setText(message);
			blog(LOG_WARNING, "[DonationAlerts Provider] OAuth token refresh returned an invalid response.");
			publish_realtime_status(false, message);
			return;
		}
		access_token_ = access_token;
		const QString rotated_refresh_token = object.value(QStringLiteral("refresh_token")).toString();
		if (!rotated_refresh_token.isEmpty())
			refresh_token_ = rotated_refresh_token;
		access_token_expires_at_ = QDateTime::currentSecsSinceEpoch() +
					   object.value(QStringLiteral("expires_in")).toInteger(3600);
		const bool saved = save_credentials();
		publish_proxy_access_token(access_token_);
		if (!donations_timer_->isActive())
			donations_timer_->start(5000);
		fetch_profile();
		poll_donations();
		if (saved)
			status_->setText(localized("OAuth.Connected"));
		blog(LOG_INFO, "[DonationAlerts Provider] Saved OAuth credentials restored; account token refreshed.");
	});
}

void ProviderPanel::restore_saved_connection()
{
	if (access_token_.isEmpty() && refresh_token_.isEmpty()) {
		const QString message = localized("OAuth.NotConfigured");
		status_->setText(message);
		blog(LOG_INFO, "[DonationAlerts Provider] %s", message.toUtf8().constData());
		publish_realtime_status(false, message);
		return;
	}

	const qint64 now = QDateTime::currentSecsSinceEpoch();
	if (!access_token_.isEmpty() && access_token_expires_at_ > now + 60) {
		blog(LOG_INFO, "[DonationAlerts Provider] Restoring the saved DonationAlerts connection.");
		status_->setText(localized("OAuth.Restoring"));
		publish_proxy_access_token(access_token_);
		donations_timer_->start(5000);
		fetch_profile();
		poll_donations();
		return;
	}

	if (!refresh_token_.isEmpty()) {
		blog(LOG_INFO, "[DonationAlerts Provider] Refreshing the saved OAuth token at OBS startup.");
		status_->setText(localized("OAuth.Restoring"));
		refresh_access_token();
		return;
	}

	const QString message = localized("OAuth.NoRefreshToken");
	status_->setText(message);
	blog(LOG_WARNING, "[DonationAlerts Provider] Saved access token is expired and no refresh token is available.");
	publish_realtime_status(false, message);
}

void ProviderPanel::fetch_profile()
{
	if (access_token_.isEmpty())
		return;
	QNetworkRequest request(QUrl(api_url(QStringLiteral("/api/v1/user/oauth"))));
	request.setRawHeader("Authorization", QByteArray("Bearer ") + access_token_.toUtf8());
	auto *reply = network_->get(request);
	connect(reply, &QNetworkReply::finished, this, [this, reply] {
		const QByteArray body = reply->readAll();
		const auto network_error = reply->error();
		const QString error_text = reply->errorString();
		reply->deleteLater();
		if (access_token_.isEmpty())
			return;
		if (network_error != QNetworkReply::NoError) {
			status_->setText(response_error(body, localized("OAuth.ProfileFailed").arg(error_text)));
			return;
		}
		QJsonParseError parse_error{};
		const auto document = QJsonDocument::fromJson(body, &parse_error);
		if (parse_error.error != QJsonParseError::NoError || !document.isObject()) {
			status_->setText(localized("OAuth.InvalidProfile"));
			return;
		}
		const auto response = document.object();
		const auto data = response.value(QStringLiteral("data")).toObject();
		add_debug_message(QStringLiteral("GET /api/v1/user/oauth — HTTP %1; fields: %2; user id: %3; Centrifugo token: %4")
					  .arg(reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt())
					  .arg(QStringList(data.keys()).join(QStringLiteral(", ")))
					  .arg(data.value(QStringLiteral("id")).toVariant().toString())
					  .arg(data.value(QStringLiteral("socket_connection_token")).toString().isEmpty()
						       ? QStringLiteral("missing")
						       : QStringLiteral("present (value hidden)")));
		QJsonObject public_profile;
		for (const auto &key : {QStringLiteral("id"), QStringLiteral("code"), QStringLiteral("name"),
					QStringLiteral("avatar")}) {
			if (data.contains(key))
				public_profile.insert(key, data.value(key));
		}
		publish_profile(public_profile);
		QString socket_token = data.value(QStringLiteral("socket_connection_token")).toString();
		if (socket_token.isEmpty())
			socket_token = response.value(QStringLiteral("socket_connection_token")).toString();
		const QString user_id = data.value(QStringLiteral("id")).toVariant().toString();
		if (socket_token.isEmpty() || user_id.isEmpty()) {
			donation_stream_->stop();
			status_->setText(localized("OAuth.RealtimeUnavailable"));
			publish_realtime_status(false, localized("OAuth.RealtimeUnavailable"));
			return;
		}

		QPointer<ProviderPanel> panel(this);
		donation_stream_->start(
			socket_token, access_token_, user_id,
			[panel](QJsonObject event) {
				if (!panel)
					return;
				QMetaObject::invokeMethod(
					panel,
					[panel, event = std::move(event)] {
						if (panel)
							panel->publish_donation_event(event);
					},
					Qt::QueuedConnection);
			},
			[panel](QString message) {
				if (!panel)
					return;
				QMetaObject::invokeMethod(
					panel,
					[panel, message = std::move(message)] {
						if (!panel)
							return;
						const bool connected =
							message.startsWith(QStringLiteral("DonationAlerts real-time socket connected"));
						QString translated;
						if (message.startsWith(QStringLiteral("Connecting to DonationAlerts")))
							translated = localized("OAuth.RealtimeConnecting");
						else if (connected)
							translated = localized("OAuth.RealtimeConnected");
						else
							translated = localized("OAuth.RealtimeError").arg(message);
						panel->status_->setText(translated);
						panel->add_debug_message(message);
						panel->publish_realtime_status(connected, translated);
					},
					Qt::QueuedConnection);
			},
			[panel](QString message) {
				if (!panel)
					return;
				QMetaObject::invokeMethod(
					panel,
					[panel, message = std::move(message)] {
						if (panel)
							panel->add_debug_message(message);
					},
					Qt::QueuedConnection);
			});
	});
}

void ProviderPanel::poll_donations()
{
	if (access_token_.isEmpty() || donation_poll_in_flight_)
		return;
	if (access_token_expires_at_ <= QDateTime::currentSecsSinceEpoch() + 60) {
		refresh_access_token();
		return;
	}
	donation_poll_in_flight_ = true;
	QNetworkRequest request(QUrl(api_url(QStringLiteral("/api/v1/alerts/donations"))));
	request.setRawHeader("Authorization", QByteArray("Bearer ") + access_token_.toUtf8());
	auto *reply = network_->get(request);
	connect(reply, &QNetworkReply::finished, this, [this, reply] {
		const QByteArray body = reply->readAll();
		const auto network_error = reply->error();
		const int status_code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
		const QString error_text = reply->errorString();
		reply->deleteLater();
		donation_poll_in_flight_ = false;
		add_debug_message(QStringLiteral("REST GET /api/v1/alerts/donations — HTTP %1\n%2")
					  .arg(status_code)
					  .arg(QString::fromUtf8(body)));
		if (network_error != QNetworkReply::NoError) {
			status_->setText(response_error(body, localized("OAuth.DonationsFailed").arg(error_text)));
			return;
		}
		QJsonParseError parse_error{};
		const auto document = QJsonDocument::fromJson(body, &parse_error);
		if (parse_error.error != QJsonParseError::NoError || !document.isObject() ||
		    !document.object().value(QStringLiteral("data")).isArray()) {
			status_->setText(localized("OAuth.InvalidDonations"));
			return;
		}
		publish_donations(document.object().value(QStringLiteral("data")).toArray());
		add_debug_message(QStringLiteral("REST: received %1 donation record(s).")
					  .arg(document.object().value(QStringLiteral("data")).toArray().size()));
		status_->setText(localized("OAuth.DataUpdated"));
	});
}

void ProviderPanel::publish_profile(const QJsonObject &profile, bool connected)
{
	QNetworkRequest request = admin_request(QStringLiteral("/api/provider/profile"), admin_token_);
	request.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));
	const QByteArray body = connected ? QJsonDocument(profile).toJson(QJsonDocument::Compact) : QByteArray("null");
	auto *reply = network_->post(request, body);
	connect(reply, &QNetworkReply::finished, this, [this, reply] {
		if (reply->error() != QNetworkReply::NoError)
			status_->setText(localized("OAuth.PublishFailed").arg(reply->errorString()));
		reply->deleteLater();
	});
}

void ProviderPanel::publish_donations(const QJsonArray &donations)
{
	QNetworkRequest request = admin_request(QStringLiteral("/api/provider/donations"), admin_token_);
	request.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));
	auto *reply = network_->post(request, QJsonDocument(donations).toJson(QJsonDocument::Compact));
	connect(reply, &QNetworkReply::finished, this, [this, reply] {
		if (reply->error() != QNetworkReply::NoError)
			status_->setText(localized("OAuth.PublishFailed").arg(reply->errorString()));
		reply->deleteLater();
	});
}

void ProviderPanel::publish_donation_event(const QJsonObject &event)
{
	QNetworkRequest request = admin_request(QStringLiteral("/api/provider/donation-event"), admin_token_);
	request.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));
	auto *reply = network_->post(request, QJsonDocument(event).toJson(QJsonDocument::Compact));
	connect(reply, &QNetworkReply::finished, this, [this, reply] {
		const QByteArray body = reply->readAll();
		const auto network_error = reply->error();
		const int status_code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
		const QString error_text = reply->errorString();
		reply->deleteLater();
		const bool failed = network_error != QNetworkReply::NoError || status_code < 200 || status_code >= 300;
		add_debug_message(QStringLiteral("POST /api/provider/donation-event — HTTP %1%2")
					  .arg(status_code)
					  .arg(!failed
						       ? QString{}
						       : QStringLiteral("; %1").arg(error_text)));
		if (failed)
			status_->setText(response_error(body, localized("OAuth.PublishFailed").arg(error_text)));
	});
}

void ProviderPanel::publish_realtime_status(bool connected, const QString &message)
{
	QNetworkRequest request = admin_request(QStringLiteral("/api/provider/realtime-status"), admin_token_);
	request.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));
	const QJsonObject status{{QStringLiteral("type"), QStringLiteral("status")},
				 {QStringLiteral("connected"), connected},
				 {QStringLiteral("message"), message}};
	auto *reply = network_->post(request, QJsonDocument(status).toJson(QJsonDocument::Compact));
	connect(reply, &QNetworkReply::finished, this, [this, reply] {
		const QByteArray body = reply->readAll();
		const auto network_error = reply->error();
		const QString error_text = reply->errorString();
		reply->deleteLater();
		if (network_error != QNetworkReply::NoError)
			status_->setText(response_error(body, localized("OAuth.PublishFailed").arg(error_text)));
	});
}

void ProviderPanel::publish_proxy_access_token(const QString &access_token)
{
	QUrlQuery form;
	form.addQueryItem(QStringLiteral("access_token"), access_token);
	QNetworkRequest request = admin_request(QStringLiteral("/api/provider/oauth-token"), admin_token_);
	request.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/x-www-form-urlencoded"));
	auto *reply = network_->post(request, form.query(QUrl::FullyEncoded).toUtf8());
	connect(reply, &QNetworkReply::finished, this, [reply] {
		const auto network_error = reply->error();
		const QString error_text = reply->errorString();
		reply->deleteLater();
		if (network_error != QNetworkReply::NoError)
			blog(LOG_WARNING, "[DonationAlerts Provider] Could not update the in-memory API proxy credentials: %s",
			     error_text.toUtf8().constData());
	});
}

void ProviderPanel::add_debug_message(const QString &message)
{
	if (!debug_enabled_->isChecked())
		return;
	constexpr qsizetype max_message_chars = 16384;
	QString content = message;
	if (content.size() > max_message_chars)
		content = content.left(max_message_chars) + QStringLiteral("\n[truncated]");
	const QString timestamp = QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss.zzz"));
	debug_output_->appendPlainText(QStringLiteral("[%1] %2").arg(timestamp, content));
}

bool ProviderPanel::save_credentials()
{
	QJsonObject credentials{
		{QStringLiteral("clientId"), client_id_->text().trimmed()},
		{QStringLiteral("clientSecret"), client_secret_->text()},
		{QStringLiteral("accessToken"), access_token_},
		{QStringLiteral("refreshToken"), refresh_token_},
		{QStringLiteral("expiresAt"), access_token_expires_at_}
	};
	const QByteArray encrypted = protect_data(QJsonDocument(credentials).toJson(QJsonDocument::Compact));
	if (encrypted.isEmpty()) {
		status_->setText(localized("OAuth.StorageFailed").arg(QString::number(GetLastError())));
		return false;
	}
	const QString path = credential_path();
	if (!QDir().mkpath(QFileInfo(path).absolutePath())) {
		status_->setText(localized("OAuth.StorageFailed").arg(QStringLiteral("directory")));
		return false;
	}
	QSaveFile file(path);
	if (!file.open(QIODevice::WriteOnly) || file.write(encrypted) != encrypted.size() || !file.commit()) {
		status_->setText(localized("OAuth.StorageFailed").arg(file.errorString()));
		return false;
	}
	return true;
}

void ProviderPanel::load_credentials()
{
	QFile file(credential_path());
	if (!file.exists())
		return;
	if (!file.open(QIODevice::ReadOnly)) {
		status_->setText(localized("OAuth.StorageReadFailed").arg(file.errorString()));
		return;
	}
	const QByteArray plain = unprotect_data(file.readAll());
	if (plain.isEmpty()) {
		status_->setText(localized("OAuth.DecryptFailed").arg(QString::number(GetLastError())));
		return;
	}
	QJsonParseError parse_error{};
	const auto document = QJsonDocument::fromJson(plain, &parse_error);
	if (parse_error.error != QJsonParseError::NoError || !document.isObject()) {
		status_->setText(localized("OAuth.InvalidStoredData"));
		return;
	}
	const auto credentials = document.object();
	client_id_->setText(credentials.value(QStringLiteral("clientId")).toString());
	client_secret_->setText(credentials.value(QStringLiteral("clientSecret")).toString());
	access_token_ = credentials.value(QStringLiteral("accessToken")).toString();
	refresh_token_ = credentials.value(QStringLiteral("refreshToken")).toString();
	access_token_expires_at_ = credentials.value(QStringLiteral("expiresAt")).toInteger();
}

void ProviderPanel::refresh_tokens()
{
	status_->setText(localized("Panel.Status.Loading"));
	set_busy(true);
	auto *reply = network_->get(admin_request(QStringLiteral("/api/widget-tokens"), admin_token_));
	connect(reply, &QNetworkReply::finished, this, [this, reply] {
		const QByteArray body = reply->readAll();
		const auto network_error = reply->error();
		const QString error_text = reply->errorString();
		reply->deleteLater();
		set_busy(false);

		if (network_error != QNetworkReply::NoError) {
			status_->setText(response_error(body, localized("Panel.Status.LoadFailed").arg(error_text)));
			return;
		}

		QJsonParseError parse_error{};
		const auto document = QJsonDocument::fromJson(body, &parse_error);
		if (parse_error.error != QJsonParseError::NoError || !document.isArray()) {
			status_->setText(localized("Panel.Status.InvalidList"));
			return;
		}

		tokens_->clear();
		for (const auto &value : document.array()) {
			const auto token = value.toObject();
			const QString name = token.value(QStringLiteral("name")).toString();
			const QJsonValue expires_at = token.value(QStringLiteral("expiresAt"));
			const QString expiration =
				expires_at.isNull()
					? localized("Panel.TokenNoExpiration")
					: QLocale().toString(
						  QDateTime::fromMSecsSinceEpoch(static_cast<qint64>(expires_at.toDouble()))
							  .toLocalTime()
							  .date(),
						  QLocale::ShortFormat);
			const QString scopes = [this, &token] {
				QStringList values;
				for (const auto &scope : token.value(QStringLiteral("scopes")).toArray()) {
					const QString scope_name = scope.toString();
					if (scope_name == QStringLiteral("read:donation-events"))
						values.append(localized("Panel.Scope.Donations"));
					else if (scope_name == QStringLiteral("read:goal-updates"))
						values.append(localized("Panel.Scope.Goals"));
					else if (scope_name == QStringLiteral("read:poll-updates"))
						values.append(localized("Panel.Scope.Polls"));
				}
				return values.join(QStringLiteral(", "));
			}();
			const bool active = token.value(QStringLiteral("active")).toBool();
			QStringList token_details{
				expires_at.isNull() ? expiration : localized("Panel.TokenExpiry").arg(expiration),
				active ? localized("Panel.TokenActive") : localized("Panel.TokenInactive"),
				scopes,
			};
			auto *item = new QListWidgetItem(QStringLiteral("%1\n%2")
							 .arg(name, token_details.join(QLatin1Char('\n'))),
						 tokens_);
			item->setData(Qt::UserRole, token.value(QStringLiteral("id")).toString());
		}
		status_->setText(localized("Panel.Status.ListUpdated"));
	});
}

void ProviderPanel::issue_token()
{
	QStringList scopes;
	if (donation_scope_->isChecked())
		scopes.append(QStringLiteral("read:donation-events"));
	if (goal_scope_->isChecked())
		scopes.append(QStringLiteral("read:goal-updates"));
	if (poll_scope_->isChecked())
		scopes.append(QStringLiteral("read:poll-updates"));
	if (scopes.isEmpty()) {
		status_->setText(localized("Panel.Status.SelectScope"));
		return;
	}

	QUrlQuery form;
	form.addQueryItem(QStringLiteral("name"), name_->text());
	const qint64 expires_at = no_expiration_->isChecked()
					  ? 0
					  : QDateTime(expiration_date_->date().addDays(1), QTime(0, 0), Qt::LocalTime)
						    .toMSecsSinceEpoch();
	form.addQueryItem(QStringLiteral("expiresAt"), QString::number(expires_at));
	form.addQueryItem(QStringLiteral("scopes"), scopes.join(QLatin1Char(',')));
	QNetworkRequest request = admin_request(QStringLiteral("/api/widget-tokens"), admin_token_);
	request.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/x-www-form-urlencoded"));

	status_->setText(localized("Panel.Status.Issuing"));
	set_busy(true);
	auto *reply = network_->post(request, form.query(QUrl::FullyEncoded).toUtf8());
	connect(reply, &QNetworkReply::finished, this, [this, reply] {
		const QByteArray body = reply->readAll();
		const auto network_error = reply->error();
		const QString error_text = reply->errorString();
		reply->deleteLater();
		set_busy(false);

		if (network_error != QNetworkReply::NoError) {
			status_->setText(response_error(body, localized("Panel.Status.IssueFailed").arg(error_text)));
			return;
		}

		QJsonParseError parse_error{};
		const auto document = QJsonDocument::fromJson(body, &parse_error);
		const QString token = document.object().value(QStringLiteral("token")).toString();
		if (parse_error.error != QJsonParseError::NoError || token.isEmpty()) {
			status_->setText(localized("Panel.Status.MissingToken"));
			return;
		}

		QDialog dialog(this);
		dialog.setWindowTitle(localized("Panel.IssueDialog.Title"));
		auto *layout = new QVBoxLayout(&dialog);
		auto *message = new QLabel(
			localized("Panel.IssueDialog.Message"), &dialog);
		message->setWordWrap(true);
		auto *token_field = new QLineEdit(token, &dialog);
		token_field->setReadOnly(true);
		auto *copy_button = new QPushButton(localized("Panel.IssueDialog.Copy"), &dialog);
		auto *close_button = new QPushButton(localized("Panel.IssueDialog.Close"), &dialog);
		auto *buttons = new QHBoxLayout;
		buttons->addWidget(copy_button);
		buttons->addWidget(close_button);
		layout->addWidget(message);
		layout->addWidget(token_field);
		layout->addLayout(buttons);
		connect(copy_button, &QPushButton::clicked, &dialog, [token] {
			QApplication::clipboard()->setText(token);
		});
		connect(close_button, &QPushButton::clicked, &dialog, &QDialog::accept);
		dialog.exec();
		status_->setText(localized("Panel.Status.Issued"));
		refresh_tokens();
	});
}

void ProviderPanel::revoke_selected_token()
{
	auto *item = tokens_->currentItem();
	if (!item)
		return;

	QUrlQuery form;
	form.addQueryItem(QStringLiteral("id"), item->data(Qt::UserRole).toString());
	QNetworkRequest request = admin_request(QStringLiteral("/api/widget-tokens/revoke"), admin_token_);
	request.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/x-www-form-urlencoded"));

	status_->setText(localized("Panel.Status.Revoking"));
	set_busy(true);
	auto *reply = network_->post(request, form.query(QUrl::FullyEncoded).toUtf8());
	connect(reply, &QNetworkReply::finished, this, [this, reply] {
		const QByteArray body = reply->readAll();
		const auto network_error = reply->error();
		const QString error_text = reply->errorString();
		reply->deleteLater();
		set_busy(false);

		if (network_error != QNetworkReply::NoError) {
			status_->setText(response_error(body, localized("Panel.Status.RevokeFailed").arg(error_text)));
			return;
		}

		const auto document = QJsonDocument::fromJson(body);
		if (!document.object().value(QStringLiteral("revoked")).toBool()) {
			status_->setText(localized("Panel.Status.TokenExpired"));
			refresh_tokens();
			return;
		}
		status_->setText(localized("Panel.Status.Revoked"));
		refresh_tokens();
	});
}
