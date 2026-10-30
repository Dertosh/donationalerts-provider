#pragma once

#include <QWidget>
#include <QString>

#include <memory>
#include <string>

class QCheckBox;
class QDateEdit;
class QJsonArray;
class QJsonObject;
class QLabel;
class QLineEdit;
class QListWidget;
class QNetworkAccessManager;
class QPlainTextEdit;
class QPushButton;
class QTimer;
class DonationStream;

class ProviderPanel final : public QWidget {
public:
	explicit ProviderPanel(std::string admin_token);
	~ProviderPanel() override;

private:
	std::string admin_token_;

	QNetworkAccessManager *network_;
	QLabel *status_;
	QPushButton *copy_status_button_;
	QLineEdit *name_;
	QCheckBox *no_expiration_;
	QDateEdit *expiration_date_;
	QCheckBox *donation_scope_;
	QCheckBox *goal_scope_;
	QCheckBox *poll_scope_;
	QListWidget *tokens_;
	QPushButton *issue_button_;
	QPushButton *refresh_button_;
	QPushButton *revoke_button_;
	QPushButton *connect_button_;
	QPushButton *disconnect_button_;
	QCheckBox *debug_enabled_;
	QPlainTextEdit *debug_output_;
	QTimer *callback_timer_;
	QTimer *donations_timer_;
	std::unique_ptr<DonationStream> donation_stream_;
	QString access_token_;
	QString refresh_token_;
	QString oauth_client_id_;
	QString oauth_state_;
	qint64 access_token_expires_at_ = 0;
	bool donation_poll_in_flight_ = false;
	bool token_refresh_in_flight_ = false;
	bool oauth_config_in_flight_ = false;
	bool credentials_migrated_ = false;
	bool oauth_flow_active_ = false;

	void load_oauth_config();
	void refresh_tokens();
	void issue_token();
	void revoke_selected_token();
	void set_busy(bool busy);
	void update_oauth_buttons();
	void connect_donationalerts();
	void poll_oauth_callback();
	void exchange_oauth_code(const QString &code);
	void refresh_access_token();
	void restore_saved_connection();
	void fetch_profile();
	void poll_donations();
	void publish_profile(const QJsonObject &profile, bool connected = true);
	void publish_donations(const QJsonArray &donations);
	void publish_donation_event(const QJsonObject &event);
	void publish_realtime_status(bool connected, const QString &message);
	void publish_proxy_access_token(const QString &access_token);
	void add_debug_message(const QString &message);
	bool save_credentials();
	void load_credentials();
};
