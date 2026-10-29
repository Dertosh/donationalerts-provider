#pragma once

#include <QWidget>
#include <QString>

#include <string>

class QCheckBox;
class QJsonArray;
class QJsonObject;
class QLabel;
class QLineEdit;
class QListWidget;
class QNetworkAccessManager;
class QPushButton;
class QSpinBox;
class QTimer;

class ProviderPanel final : public QWidget {
public:
	explicit ProviderPanel(std::string admin_token);

private:
	std::string admin_token_;

	QNetworkAccessManager *network_;
	QLabel *status_;
	QLineEdit *name_;
	QSpinBox *lifetime_;
	QCheckBox *donation_scope_;
	QCheckBox *goal_scope_;
	QCheckBox *poll_scope_;
	QListWidget *tokens_;
	QLineEdit *client_id_;
	QLineEdit *client_secret_;
	QPushButton *issue_button_;
	QPushButton *refresh_button_;
	QPushButton *revoke_button_;
	QPushButton *connect_button_;
	QPushButton *disconnect_button_;
	QTimer *callback_timer_;
	QTimer *donations_timer_;
	QString access_token_;
	QString refresh_token_;
	QString oauth_state_;
	qint64 access_token_expires_at_ = 0;
	bool donation_poll_in_flight_ = false;
	bool token_refresh_in_flight_ = false;

	void refresh_tokens();
	void issue_token();
	void revoke_selected_token();
	void set_busy(bool busy);
	void connect_donationalerts();
	void poll_oauth_callback();
	void exchange_oauth_code(const QString &code);
	void refresh_access_token();
	void fetch_profile();
	void poll_donations();
	void publish_profile(const QJsonObject &profile, bool connected = true);
	void publish_donations(const QJsonArray &donations);
	bool save_credentials();
	void load_credentials();
};
