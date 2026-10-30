#include "donation_stream.hpp"

#include <obs-module.h>

#include <windows.h>
#include <winhttp.h>

#include <QDateTime>
#include <QByteArray>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonParseError>

#include <array>
#include <chrono>
#include <string_view>
#include <utility>
#include <vector>

namespace {

constexpr wchar_t kApiHost[] = L"www.donationalerts.com";
constexpr wchar_t kSocketHost[] = L"centrifugo.donationalerts.com";
constexpr wchar_t kSocketPath[] = L"/connection/websocket";
constexpr std::size_t kMaxMessageBytes = 1024 * 1024;
constexpr int kHttpTimeoutMs = 10000;

class WinHttpHandle {
public:
	explicit WinHttpHandle(HINTERNET handle = nullptr) : handle_(handle) {}
	~WinHttpHandle()
	{
		if (handle_)
			WinHttpCloseHandle(handle_);
	}
	WinHttpHandle(const WinHttpHandle &) = delete;
	WinHttpHandle &operator=(const WinHttpHandle &) = delete;
	HINTERNET get() const { return handle_; }

private:
	HINTERNET handle_;
};

struct HttpResult {
	DWORD status = 0;
	std::string body;
	DWORD error = ERROR_SUCCESS;
};

HttpResult post_subscribe_request(std::string_view access_token, std::string_view body)
{
	WinHttpHandle session(WinHttpOpen(L"DonationAlerts OBS Provider/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
					 WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
	if (!session.get())
		return {0, {}, GetLastError()};
	WinHttpSetTimeouts(session.get(), kHttpTimeoutMs, kHttpTimeoutMs, kHttpTimeoutMs, kHttpTimeoutMs);
	WinHttpHandle connection(WinHttpConnect(session.get(), kApiHost, INTERNET_DEFAULT_HTTPS_PORT, 0));
	if (!connection.get())
		return {0, {}, GetLastError()};
	WinHttpHandle request(WinHttpOpenRequest(connection.get(), L"POST", L"/api/v1/centrifuge/subscribe",
						 nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
						 WINHTTP_FLAG_SECURE));
	if (!request.get())
		return {0, {}, GetLastError()};

	std::wstring headers = L"Authorization: Bearer ";
	for (const unsigned char ch : access_token)
		headers.push_back(static_cast<wchar_t>(ch));
	headers += L"\r\nContent-Type: application/json\r\n";
	if (!WinHttpSendRequest(request.get(), headers.c_str(), static_cast<DWORD>(headers.size()),
				const_cast<char *>(body.data()), static_cast<DWORD>(body.size()),
				static_cast<DWORD>(body.size()), 0))
		return {0, {}, GetLastError()};
	if (!WinHttpReceiveResponse(request.get(), nullptr))
		return {0, {}, GetLastError()};

	DWORD status = 0;
	DWORD status_size = sizeof(status);
	if (!WinHttpQueryHeaders(request.get(), WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
				 WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_size, WINHTTP_NO_HEADER_INDEX))
		return {0, {}, GetLastError()};

	std::string response_body;
	for (;;) {
		DWORD available = 0;
		if (!WinHttpQueryDataAvailable(request.get(), &available))
			return {status, {}, GetLastError()};
		if (available == 0)
			break;
		if (response_body.size() + available > 64 * 1024)
			return {status, {}, ERROR_INSUFFICIENT_BUFFER};
		const auto offset = response_body.size();
		response_body.resize(offset + available);
		DWORD received = 0;
		if (!WinHttpReadData(request.get(), response_body.data() + offset, available, &received))
			return {status, {}, GetLastError()};
		response_body.resize(offset + received);
	}
	return {status, std::move(response_body), ERROR_SUCCESS};
}

QJsonObject response_json(std::string_view body)
{
	QJsonParseError error{};
	const auto document = QJsonDocument::fromJson(QByteArray(body.data(), static_cast<qsizetype>(body.size())),
						      &error);
	return error.error == QJsonParseError::NoError && document.isObject() ? document.object() : QJsonObject{};
}

QJsonValue redact_json_value(const QJsonValue &value)
{
	if (value.isArray()) {
		QJsonArray redacted;
		for (const auto &item : value.toArray())
			redacted.append(redact_json_value(item));
		return redacted;
	}
	if (!value.isObject())
		return value;

	QJsonObject redacted;
	const auto object = value.toObject();
	for (auto iterator = object.begin(); iterator != object.end(); ++iterator) {
		const QString key = iterator.key();
		if (key.contains(QStringLiteral("token"), Qt::CaseInsensitive) ||
		    key.contains(QStringLiteral("secret"), Qt::CaseInsensitive) ||
		    key.contains(QStringLiteral("password"), Qt::CaseInsensitive))
			redacted.insert(iterator.key(), QStringLiteral("[redacted]"));
		else
			redacted.insert(iterator.key(), redact_json_value(iterator.value()));
	}
	return redacted;
}

QString debug_json_message(QStringView prefix, std::string_view message)
{
	const QByteArray bytes(message.data(), static_cast<qsizetype>(message.size()));
	QJsonParseError error{};
	const auto document = QJsonDocument::fromJson(bytes, &error);
	if (error.error != QJsonParseError::NoError)
		return prefix.toString() + QString::fromUtf8(bytes);
	const auto redacted = redact_json_value(document.isObject() ? QJsonValue(document.object())
								 : QJsonValue(document.array()));
	const QJsonDocument safe_document = redacted.isObject()
		? QJsonDocument(redacted.toObject())
		: QJsonDocument(redacted.toArray());
	return prefix.toString() + QString::fromUtf8(safe_document.toJson(QJsonDocument::Indented));
}

QJsonValue decoded_json_value(QJsonValue value)
{
	if (!value.isString())
		return value;
	const QByteArray bytes = value.toString().toUtf8();
	QJsonParseError error{};
	const auto document = QJsonDocument::fromJson(bytes, &error);
	if (error.error != QJsonParseError::NoError)
		return value;
	if (document.isObject())
		return document.object();
	if (document.isArray())
		return document.array();
	return value;
}

QJsonObject donation_payload(const QJsonValue &value, int depth = 0)
{
	const QJsonValue decoded = decoded_json_value(value);
	if (decoded.isArray()) {
		const auto array = decoded.toArray();
		if (!array.isEmpty())
			return donation_payload(array.first(), depth + 1);
		return {{QStringLiteral("raw"), decoded}};
	}
	QJsonObject object = decoded.toObject();
	if (object.isEmpty())
		return {{QStringLiteral("raw"), decoded}};
	if (depth >= 4)
		return object;
	static const std::array<QString, 6> nested_keys = {
		QStringLiteral("donation"), QStringLiteral("data"), QStringLiteral("payload"),
		QStringLiteral("alert"), QStringLiteral("info"), QStringLiteral("event")
	};
	if (object.contains(QStringLiteral("amount")) || depth >= 4)
		return object;
	for (const auto &key : nested_keys) {
		const QJsonValue nested_value = decoded_json_value(object.value(key));
		if (nested_value.isObject() || nested_value.isArray())
			return donation_payload(nested_value, depth + 1);
	}
	return object;
}

bool receive_message(HINTERNET websocket, std::string &message, DWORD &error)
{
	message.clear();
	for (;;) {
		std::array<char, 8192> buffer{};
		DWORD received = 0;
		WINHTTP_WEB_SOCKET_BUFFER_TYPE type{};
		const DWORD result = WinHttpWebSocketReceive(websocket, buffer.data(),
							    static_cast<DWORD>(buffer.size()), &received, &type);
		if (result != NO_ERROR) {
			error = result;
			return false;
		}
		if (type == WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE) {
			error = ERROR_CONNECTION_ABORTED;
			return false;
		}
		if (type == WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE ||
		    type == WINHTTP_WEB_SOCKET_BINARY_FRAGMENT_BUFFER_TYPE) {
			error = ERROR_INVALID_DATA;
			return false;
		}
		if (message.size() + received > kMaxMessageBytes) {
			error = ERROR_INSUFFICIENT_BUFFER;
			return false;
		}
		message.append(buffer.data(), received);
		if (type == WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE)
			return true;
	}
}

bool send_json(HINTERNET websocket, const QJsonObject &object, DWORD &error)
{
	const QByteArray bytes = QJsonDocument(object).toJson(QJsonDocument::Compact);
	error = WinHttpWebSocketSend(websocket, WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE,
				     const_cast<char *>(bytes.constData()), static_cast<DWORD>(bytes.size()));
	return error == NO_ERROR;
}

bool connect_and_subscribe(std::stop_token stop_token, HINTERNET connection, std::string_view socket_token,
			   std::string_view access_token, std::string_view user_id, HINTERNET &websocket,
			   std::atomic<void *> &active_websocket, std::string &error_message,
			   const DonationStream::DebugCallback &on_debug)
{
	WinHttpHandle request(WinHttpOpenRequest(connection, L"GET", kSocketPath, nullptr,
						 WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
						 WINHTTP_FLAG_SECURE));
	if (!request.get()) {
		error_message = "Could not create the DonationAlerts WebSocket request.";
		return false;
	}
	if (!WinHttpSetOption(request.get(), WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, nullptr, 0) ||
	    !WinHttpSendRequest(request.get(), WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
	    !WinHttpReceiveResponse(request.get(), nullptr)) {
		error_message = "DonationAlerts WebSocket handshake failed (WinHTTP " +
				std::to_string(GetLastError()) + ").";
		return false;
	}
	DWORD status = 0;
	DWORD status_size = sizeof(status);
	if (!WinHttpQueryHeaders(request.get(), WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
				 WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_size, WINHTTP_NO_HEADER_INDEX) ||
	    status != 101) {
		error_message = "DonationAlerts rejected the WebSocket handshake (HTTP " +
				std::to_string(status) + ").";
		return false;
	}
	websocket = WinHttpWebSocketCompleteUpgrade(request.get(), 0);
	if (!websocket) {
		error_message = "Could not complete the DonationAlerts WebSocket handshake (WinHTTP " +
				std::to_string(GetLastError()) + ").";
		return false;
	}
	active_websocket.store(websocket);
	if (stop_token.stop_requested()) {
		error_message = "DonationAlerts real-time connection was stopped.";
		return false;
	}

	QJsonObject connect_params{{QStringLiteral("token"),
				    QString::fromUtf8(socket_token.data(), static_cast<qsizetype>(socket_token.size()))}};
	if (!send_json(websocket, {{QStringLiteral("id"), 1}, {QStringLiteral("params"), connect_params}}, status)) {
		error_message = "Could not send the Centrifugo connection token.";
		return false;
	}

	std::string message;
	bool connected = false;
	std::string client_id;
	while (!stop_token.stop_requested()) {
		DWORD receive_error = ERROR_SUCCESS;
		if (!receive_message(websocket, message, receive_error)) {
			error_message = "DonationAlerts WebSocket closed during connection (WinHTTP " +
					std::to_string(receive_error) + ").";
			return false;
		}
		if (on_debug)
			on_debug(debug_json_message(QStringLiteral("Centrifugo → "), message));
		const auto response = response_json(message);
		if (response.value(QStringLiteral("id")).toInt() != 1)
			continue;
		const auto result = response.value(QStringLiteral("result")).toObject();
		client_id = result.value(QStringLiteral("client")).toString().toStdString();
		if (client_id.empty()) {
			error_message = "DonationAlerts did not return a Centrifugo client ID.";
			return false;
		}
		connected = true;
		break;
	}
	if (!connected || stop_token.stop_requested())
		return false;

	const std::string channel = "$alerts:donation_" + std::string(user_id);
	QJsonObject subscribe_request{
		{QStringLiteral("channels"), QJsonArray{QString::fromStdString(channel)}},
		{QStringLiteral("client"), QString::fromStdString(client_id)}
	};
	const auto subscribe_response = post_subscribe_request(
		access_token, QJsonDocument(subscribe_request).toJson(QJsonDocument::Compact).toStdString());
	if (on_debug) {
		const QString response = subscribe_response.body.empty()
			? QStringLiteral("[empty]")
			: debug_json_message(QStringLiteral(""), subscribe_response.body);
		on_debug(QStringLiteral("POST /api/v1/centrifuge/subscribe — HTTP %1\n%2")
				 .arg(subscribe_response.status)
				 .arg(response));
	}
	if (subscribe_response.error != ERROR_SUCCESS || subscribe_response.status < 200 ||
	    subscribe_response.status >= 300) {
		error_message = "DonationAlerts channel subscription failed";
		if (subscribe_response.status != 0)
			error_message += " (HTTP " + std::to_string(subscribe_response.status) + ")";
		else
			error_message += " (WinHTTP " + std::to_string(subscribe_response.error) + ")";
		error_message += ".";
		return false;
	}
	const auto subscription = response_json(subscribe_response.body);
	const auto channels = subscription.value(QStringLiteral("channels")).toArray();
	if (channels.isEmpty()) {
		error_message = "DonationAlerts returned no authorized donation channel.";
		return false;
	}
	const auto channel_info = channels.first().toObject();
	const QString authorized_channel = channel_info.value(QStringLiteral("channel")).toString();
	const QString channel_token = channel_info.value(QStringLiteral("token")).toString();
	if (authorized_channel != QString::fromStdString(channel) || channel_token.isEmpty()) {
		error_message = "DonationAlerts returned an invalid channel subscription.";
		return false;
	}
	QJsonObject channel_params{{QStringLiteral("channel"), authorized_channel},
				   {QStringLiteral("token"), channel_token}};
	if (!send_json(websocket,
		       {{QStringLiteral("id"), 2}, {QStringLiteral("method"), 1},
			{QStringLiteral("params"), channel_params}},
		       status)) {
		error_message = "Could not subscribe to the DonationAlerts donation channel.";
		return false;
	}

	while (!stop_token.stop_requested()) {
		DWORD receive_error = ERROR_SUCCESS;
		if (!receive_message(websocket, message, receive_error)) {
			error_message = "DonationAlerts WebSocket disconnected (WinHTTP " +
					std::to_string(receive_error) + ").";
			return false;
		}
		if (on_debug)
			on_debug(debug_json_message(QStringLiteral("Centrifugo → "), message));
		const auto response = response_json(message);
		if (response.value(QStringLiteral("id")).toInt() == 2) {
			const auto result = response.value(QStringLiteral("result")).toObject();
			if (on_debug)
				on_debug(QStringLiteral("Centrifugo subscription acknowledgement:\n%1")
						 .arg(QString::fromUtf8(QJsonDocument(result).toJson(QJsonDocument::Indented))));
			if (response.contains(QStringLiteral("error"))) {
				const auto server_error = response.value(QStringLiteral("error")).toObject();
				const QString reason = server_error.value(QStringLiteral("message")).toString();
				error_message = reason.isEmpty()
					? "DonationAlerts rejected the donation channel subscription."
					: "DonationAlerts rejected the donation channel subscription: " + reason.toStdString();
				return false;
			}
			const QString confirmed_channel = result.value(QStringLiteral("channel")).toString();
			if (!confirmed_channel.isEmpty() && confirmed_channel != authorized_channel) {
				error_message = "DonationAlerts subscription acknowledgement channel mismatch (expected '" +
						authorized_channel.toStdString() + "', received '" +
						confirmed_channel.toStdString() + "').";
				return false;
			}
			const QJsonValue type = result.value(QStringLiteral("type"));
			if (!type.isUndefined() && type.toInt(-1) != 1) {
				error_message = "DonationAlerts acknowledged the requested channel with an unexpected "
						"subscription type (" + type.toVariant().toString().toStdString() + ").";
				return false;
			}
			if (!response.value(QStringLiteral("result")).isObject()) {
				error_message = "DonationAlerts subscription acknowledgement did not contain a result object.";
				return false;
			}
			if (confirmed_channel.isEmpty() && on_debug)
				on_debug(QStringLiteral("Centrifugo acknowledgement has no channel field; accepting command-id "
							"confirmation with subscription recovery metadata."));
			return true;
		}
	}
	return false;
}

} // namespace

DonationStream::~DonationStream()
{
	stop();
}

void DonationStream::start(QString socket_token, QString access_token, QString user_id, EventCallback on_event,
			   StatusCallback on_status, DebugCallback on_debug)
{
	stop();
	if (socket_token.isEmpty() || access_token.isEmpty() || user_id.isEmpty()) {
		if (on_status)
			on_status(QStringLiteral("DonationAlerts real-time connection data is incomplete."));
		return;
	}
	worker_ = std::jthread([this, socket_token = std::move(socket_token),
				access_token = std::move(access_token), user_id = std::move(user_id),
				on_event = std::move(on_event), on_status = std::move(on_status),
				on_debug = std::move(on_debug)](std::stop_token stop_token) {
		if (on_status)
			on_status(QStringLiteral("Connecting to DonationAlerts real-time events…"));
		int retry_delay_seconds = 3;
		while (!stop_token.stop_requested()) {
			WinHttpHandle session(WinHttpOpen(L"DonationAlerts OBS Provider/1.0",
							  WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME,
							  WINHTTP_NO_PROXY_BYPASS, 0));
			if (!session.get()) {
				const QString message = QStringLiteral("Could not initialize WinHTTP for the realtime connection.");
				blog(LOG_WARNING, "[DonationAlerts Provider] %s", message.toUtf8().constData());
				if (on_status)
					on_status(message);
			} else {
				WinHttpSetTimeouts(session.get(), kHttpTimeoutMs, kHttpTimeoutMs, kHttpTimeoutMs,
						   kHttpTimeoutMs);
				WinHttpHandle connection(
					WinHttpConnect(session.get(), kSocketHost, INTERNET_DEFAULT_HTTPS_PORT, 0));
				HINTERNET websocket = nullptr;
				std::string error_message;
				const bool connected = connection.get()
					? connect_and_subscribe(stop_token, connection.get(), socket_token.toStdString(),
								access_token.toStdString(), user_id.toStdString(), websocket,
								active_websocket_, error_message, on_debug)
					: false;
				if (!connection.get())
					error_message = "Could not connect to DonationAlerts Centrifugo.";
				if (websocket) {
					if (connected) {
						blog(LOG_INFO, "[DonationAlerts Provider] Realtime donation channel subscribed.");
						if (on_status)
							on_status(QStringLiteral("DonationAlerts real-time socket connected."));
					}
					if (connected) {
						std::string message;
						const QString expected_channel =
							QStringLiteral("$alerts:donation_%1").arg(user_id);
						while (!stop_token.stop_requested()) {
							DWORD receive_error = ERROR_SUCCESS;
							if (!receive_message(websocket, message, receive_error)) {
								error_message = "DonationAlerts WebSocket disconnected (WinHTTP " +
										std::to_string(receive_error) + ").";
								break;
							}
							if (on_debug)
								on_debug(debug_json_message(QStringLiteral("Centrifugo → "), message));
							const auto response = response_json(message);
							const auto push = response.value(QStringLiteral("push")).toObject();
							const auto publication = push.value(QStringLiteral("pub")).toObject();
							QJsonValue data;
							if (!publication.isEmpty()) {
								const QString channel = publication.value(QStringLiteral("channel")).toString();
								if (!channel.isEmpty() && channel != expected_channel)
									continue;
								data = publication.value(QStringLiteral("data"));
							} else {
								const auto result = response.value(QStringLiteral("result")).toObject();
								if (result.value(QStringLiteral("channel")).toString() != expected_channel)
									continue;
								data = result.value(QStringLiteral("data"));
							}
							if (data.isUndefined() || data.isNull())
								continue;
							const auto donation = donation_payload(data);
							blog(LOG_INFO, "[DonationAlerts Provider] Received a realtime donation publication.");
							on_event({{QStringLiteral("type"), QStringLiteral("donation")},
								  {QStringLiteral("donation"), donation},
								  {QStringLiteral("receivedAt"), QDateTime::currentDateTimeUtc()
													       .toString(Qt::ISODateWithMs)}});
						}
					}
					HINTERNET expected = websocket;
					if (active_websocket_.compare_exchange_strong(expected, nullptr))
						WinHttpCloseHandle(websocket);
				}
				if (!stop_token.stop_requested()) {
					const QString message = QString::fromStdString(
						error_message.empty() ? "DonationAlerts real-time socket disconnected." : error_message);
					blog(LOG_WARNING, "[DonationAlerts Provider] %s", message.toUtf8().constData());
					if (on_status)
						on_status(message);
				}
			}
			for (int wait = 0; wait < 30 && !stop_token.stop_requested(); ++wait)
				std::this_thread::sleep_for(std::chrono::milliseconds(100));
			if (stop_token.stop_requested())
				break;
			for (int wait = 0; wait < retry_delay_seconds * 10 && !stop_token.stop_requested(); ++wait)
				std::this_thread::sleep_for(std::chrono::milliseconds(100));
			retry_delay_seconds = std::min(retry_delay_seconds * 2, 60);
		}
	});
}

void DonationStream::stop()
{
	if (!worker_.joinable())
		return;
	worker_.request_stop();
	if (auto websocket = static_cast<HINTERNET>(active_websocket_.exchange(nullptr)))
		WinHttpCloseHandle(websocket);
	worker_.join();
}
