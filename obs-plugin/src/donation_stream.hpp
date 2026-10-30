#pragma once

#include <QJsonObject>
#include <QString>

#include <atomic>
#include <functional>
#include <string>
#include <thread>

class DonationStream {
public:
	using EventCallback = std::function<void(QJsonObject)>;
	using StatusCallback = std::function<void(QString)>;
	using DebugCallback = std::function<void(QString)>;

	DonationStream() = default;
	~DonationStream();

	DonationStream(const DonationStream &) = delete;
	DonationStream &operator=(const DonationStream &) = delete;

	void start(QString socket_token, QString access_token, QString user_id, EventCallback on_event,
		   StatusCallback on_status, DebugCallback on_debug);
	void stop();

private:
	std::jthread worker_;
	std::atomic<void *> active_websocket_{nullptr};
};
