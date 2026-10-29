#include "provider_panel.hpp"

#include <obs-module.h>

#include <windows.h>
#include <wincrypt.h>

#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QDateTime>
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
#include <QPushButton>
#include <QRandomGenerator>
#include <QSaveFile>
#include <QSpinBox>
#include <QStringList>
#include <QTimer>
#include <QUrl>
#include <QUrlQuery>
#include <QVBoxLayout>

#include <cstdint>
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

} // namespace

ProviderPanel::ProviderPanel(std::string admin_token)
	: admin_token_(std::move(admin_token)),
	  network_(new QNetworkAccessManager(this)),
	  status_(new QLabel(this)),
	  name_(new QLineEdit(QStringLiteral("obs-widget"), this)),
	  lifetime_(new QSpinBox(this)),
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
	  callback_timer_(new QTimer(this)),
	  donations_timer_(new QTimer(this))
{
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
	lifetime_->setRange(1, 1440);
	lifetime_->setValue(60);
	lifetime_->setSuffix(localized("Panel.Minutes"));
	form->addRow(localized("Panel.TokenName"), name_);
	form->addRow(localized("Panel.TokenLifetime"), lifetime_);
	layout->addLayout(form);

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
	layout->addWidget(status_);

	revoke_button_->setEnabled(false);
	connect(issue_button_, &QPushButton::clicked, this, [this] { issue_token(); });
	connect(refresh_button_, &QPushButton::clicked, this, [this] { refresh_tokens(); });
	connect(revoke_button_, &QPushButton::clicked, this, [this] { revoke_selected_token(); });
	connect(connect_button_, &QPushButton::clicked, this, [this] { connect_donationalerts(); });
	connect(disconnect_button_, &QPushButton::clicked, this, [this] {
		callback_timer_->stop();
		donations_timer_->stop();
		access_token_.clear();
		refresh_token_.clear();
		access_token_expires_at_ = 0;
		QFile::remove(credential_path());
		status_->setText(localized("OAuth.Disconnected"));
		publish_profile(QJsonObject{}, false);
		publish_donations(QJsonArray{});
	});
	connect(tokens_, &QListWidget::itemSelectionChanged, this, [this] {
		revoke_button_->setEnabled(tokens_->currentItem() != nullptr);
	});
	connect(callback_timer_, &QTimer::timeout, this, [this] { poll_oauth_callback(); });
	connect(donations_timer_, &QTimer::timeout, this, [this] { poll_donations(); });

	load_credentials();
	refresh_tokens();
	if (!refresh_token_.isEmpty()) {
		const qint64 now = QDateTime::currentSecsSinceEpoch();
		if (access_token_.isEmpty() || access_token_expires_at_ <= now + 60)
			refresh_access_token();
		else {
			donations_timer_->start(5000);
			fetch_profile();
			poll_donations();
		}
	}
}

void ProviderPanel::set_busy(bool busy)
{
	issue_button_->setEnabled(!busy);
	refresh_button_->setEnabled(!busy);
	revoke_button_->setEnabled(!busy && tokens_->currentItem() != nullptr);
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
			status_->setText(localized("OAuth.AuthorizationFailed").arg(error));
			return;
		}
		if (code.isEmpty())
			return;
		callback_timer_->stop();
		if (callback.value(QStringLiteral("state")).toString() != oauth_state_) {
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
			status_->setText(response_error(body, localized("OAuth.ExchangeFailed").arg(error_text)));
			return;
		}

		QJsonParseError parse_error{};
		const auto document = QJsonDocument::fromJson(body, &parse_error);
		const auto object = document.object();
		const QString access_token = object.value(QStringLiteral("access_token")).toString();
		if (parse_error.error != QJsonParseError::NoError || access_token.isEmpty()) {
			status_->setText(response_error(body, localized("OAuth.InvalidTokenResponse")));
			return;
		}
		access_token_ = access_token;
		refresh_token_ = object.value(QStringLiteral("refresh_token")).toString();
		access_token_expires_at_ = QDateTime::currentSecsSinceEpoch() +
					   object.value(QStringLiteral("expires_in")).toInteger(3600);
		const bool saved = save_credentials();
		donations_timer_->start(5000);
		if (saved)
			status_->setText(localized("OAuth.Connected"));
		fetch_profile();
		poll_donations();
	});
}

void ProviderPanel::refresh_access_token()
{
	if (token_refresh_in_flight_ || refresh_token_.isEmpty())
		return;
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
			status_->setText(response_error(body, localized("OAuth.RefreshFailed").arg(error_text)));
			return;
		}

		QJsonParseError parse_error{};
		const auto document = QJsonDocument::fromJson(body, &parse_error);
		const auto object = document.object();
		const QString access_token = object.value(QStringLiteral("access_token")).toString();
		if (parse_error.error != QJsonParseError::NoError || access_token.isEmpty()) {
			status_->setText(response_error(body, localized("OAuth.InvalidTokenResponse")));
			return;
		}
		access_token_ = access_token;
		const QString rotated_refresh_token = object.value(QStringLiteral("refresh_token")).toString();
		if (!rotated_refresh_token.isEmpty())
			refresh_token_ = rotated_refresh_token;
		access_token_expires_at_ = QDateTime::currentSecsSinceEpoch() +
					   object.value(QStringLiteral("expires_in")).toInteger(3600);
		const bool saved = save_credentials();
		if (!donations_timer_->isActive())
			donations_timer_->start(5000);
		fetch_profile();
		poll_donations();
		if (saved)
			status_->setText(localized("OAuth.Connected"));
	});
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
		const auto data = document.object().value(QStringLiteral("data")).toObject();
		QJsonObject public_profile;
		for (const auto &key : {QStringLiteral("id"), QStringLiteral("code"), QStringLiteral("name"),
					QStringLiteral("avatar")}) {
			if (data.contains(key))
				public_profile.insert(key, data.value(key));
		}
		publish_profile(public_profile);
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
		const QString error_text = reply->errorString();
		reply->deleteLater();
		donation_poll_in_flight_ = false;
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
			const qint64 expires_at = static_cast<qint64>(token.value(QStringLiteral("expiresAt")).toDouble());
			const QString expiration = QDateTime::fromMSecsSinceEpoch(expires_at).toLocalTime().toString(
				QLocale().dateTimeFormat(QLocale::ShortFormat));
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
			auto *item = new QListWidgetItem(
				QStringLiteral("%1\n%2\n%3").arg(name, localized("Panel.TokenExpiry").arg(expiration), scopes),
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
	form.addQueryItem(QStringLiteral("expiresInMinutes"), QString::number(lifetime_->value()));
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
