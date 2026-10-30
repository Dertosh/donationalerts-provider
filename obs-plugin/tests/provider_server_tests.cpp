#include "provider_server.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <cstdlib>
#include <array>
#include <atomic>
#include <cstdint>
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <string_view>

namespace {

constexpr std::uint16_t kTestPort = 4042;
constexpr std::uint16_t kWidgetEventsPort = 4045;

[[noreturn]] void fail(std::string_view message)
{
	std::cerr << "FAIL: " << message << '\n';
	std::exit(EXIT_FAILURE);
}

void require(bool condition, std::string_view message)
{
	if (!condition)
		fail(message);
}

std::wstring temporary_token_store_path()
{
	wchar_t directory[MAX_PATH]{};
	const DWORD directory_length = GetTempPathW(MAX_PATH, directory);
	require(directory_length > 0 && directory_length < MAX_PATH, "get temporary directory");
	wchar_t path[MAX_PATH]{};
	require(GetTempFileNameW(directory, L"dat", 0, path) != 0, "create temporary token store path");
	require(DeleteFileW(path) != 0, "prepare temporary token store path");
	return path;
}

std::string request(ProviderServer &server, std::string_view method, std::string_view path,
		    std::string_view body = {}, const std::map<std::string, std::string, std::less<>> &headers = {},
		    std::uint16_t port = kTestPort, std::string_view host = {})
{
	sockaddr_in address{};
	address.sin_family = AF_INET;
	address.sin_port = htons(port);
	require(InetPtonA(AF_INET, "127.0.0.1", &address.sin_addr) == 1, "parse localhost address");
	int connection_error = 0;
	SOCKET client = INVALID_SOCKET;
	bool connected = false;
	for (int attempt = 0; attempt < 40; ++attempt) {
		client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		require(client != INVALID_SOCKET, "create client socket");
		if (connect(client, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) != SOCKET_ERROR) {
			connected = true;
			break;
		}
		connection_error = WSAGetLastError();
		closesocket(client);
		client = INVALID_SOCKET;
		Sleep(50);
	}
	if (!connected) {
		closesocket(client);
		fail("connect to provider (Winsock " + std::to_string(connection_error) + ")");
	}

	const std::string host_header = host.empty() ? "127.0.0.1:" + std::to_string(port) : std::string(host);
	std::string raw = std::string(method) + " " + std::string(path) + " HTTP/1.1\r\n"
			  "Host: " + host_header + "\r\n"
			  "Connection: close\r\n";
	if (!body.empty())
		raw += "Content-Length: " + std::to_string(body.size()) + "\r\n";
	for (const auto &[key, value] : headers)
		raw += key + ": " + value + "\r\n";
	raw += "\r\n";
	raw += body;

	std::size_t sent_bytes = 0;
	while (sent_bytes < raw.size()) {
		const int sent = send(client, raw.data() + sent_bytes, static_cast<int>(raw.size() - sent_bytes), 0);
		require(sent > 0, "send HTTP request");
		sent_bytes += static_cast<std::size_t>(sent);
	}

	std::string response;
	char buffer[2048];
	for (;;) {
		const int received = recv(client, buffer, sizeof(buffer), 0);
		if (received <= 0)
			break;
		response.append(buffer, static_cast<std::size_t>(received));
	}
	shutdown(client, SD_BOTH);
	closesocket(client);
	return response;
}

int status_code(std::string_view response)
{
	const auto first_space = response.find(' ');
	if (first_space == std::string_view::npos || first_space + 4 > response.size())
		return 0;
	return std::atoi(std::string(response.substr(first_space + 1, 3)).c_str());
}

std::string_view response_body(std::string_view response)
{
	const auto separator = response.find("\r\n\r\n");
	if (separator == std::string_view::npos)
		return {};
	return response.substr(separator + 4);
}

std::string json_string_field(std::string_view json, std::string_view field)
{
	const std::string marker = "\"" + std::string(field) + "\":\"";
	const auto start = json.find(marker);
	if (start == std::string_view::npos)
		return {};
	const auto value_start = start + marker.size();
	const auto end = json.find('"', value_start);
	if (end == std::string_view::npos)
		return {};
	return std::string(json.substr(value_start, end - value_start));
}

SOCKET connect_widget_socket(std::string_view token)
{
	sockaddr_in address{};
	address.sin_family = AF_INET;
	address.sin_port = htons(kWidgetEventsPort);
	require(InetPtonA(AF_INET, "127.0.0.1", &address.sin_addr) == 1, "parse widget socket address");
	SOCKET client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	require(client != INVALID_SOCKET, "create widget event socket");
	bool connected = false;
	for (int attempt = 0; attempt < 40; ++attempt) {
		if (connect(client, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) != SOCKET_ERROR) {
			connected = true;
			break;
		}
		Sleep(50);
	}
	require(connected, "connect to widget event socket");

	const std::string request_text =
		"GET /api/widget/events HTTP/1.1\r\n"
		"Host: 127.0.0.1:" + std::to_string(kWidgetEventsPort) + "\r\n"
		"Origin: null\r\n"
		"Upgrade: websocket\r\n"
		"Connection: Upgrade\r\n"
		"Sec-WebSocket-Protocol: donationalerts-widget-v1, " + std::string(token) + "\r\n"
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
		"Sec-WebSocket-Version: 13\r\n\r\n";
	require(send(client, request_text.data(), static_cast<int>(request_text.size()), 0) ==
			static_cast<int>(request_text.size()),
		"send widget WebSocket handshake");
	std::string response;
	char byte = '\0';
	while (!response.ends_with("\r\n\r\n")) {
		require(recv(client, &byte, 1, 0) == 1, "receive widget WebSocket handshake");
		response.push_back(byte);
	}
	require(response.starts_with("HTTP/1.1 101 Switching Protocols"), "accept authorized widget WebSocket");
	DWORD timeout = 3000;
	setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char *>(&timeout), sizeof(timeout));
	return client;
}

std::string receive_widget_event(SOCKET client)
{
	std::array<unsigned char, 2> header{};
	require(recv(client, reinterpret_cast<char *>(header.data()), static_cast<int>(header.size()), MSG_WAITALL) ==
			static_cast<int>(header.size()),
		"receive widget event frame header");
	require((header[0] & 0x0f) == 0x1 && (header[1] & 0x80) == 0, "receive unmasked text event frame");
	std::uint64_t size = header[1] & 0x7f;
	if (size == 126) {
		std::array<unsigned char, 2> extended{};
		require(recv(client, reinterpret_cast<char *>(extended.data()), static_cast<int>(extended.size()),
			     MSG_WAITALL) == static_cast<int>(extended.size()),
			"receive extended widget event size");
		size = (static_cast<std::uint64_t>(extended[0]) << 8) | extended[1];
	}
	require(size <= 1024 * 1024, "widget event payload stays within supported size");
	std::string payload(static_cast<std::size_t>(size), '\0');
	require(recv(client, payload.data(), static_cast<int>(payload.size()), MSG_WAITALL) ==
			static_cast<int>(payload.size()),
		"receive widget event payload");
	return payload;
}

std::map<std::string, std::string, std::less<>> admin_headers(const ProviderServer &server)
{
	return {{"X-Admin-Token", server.admin_token()},
		{"Origin", "http://127.0.0.1:4042"},
		{"Content-Type", "application/x-www-form-urlencoded"}};
}

} // namespace

int main()
{
	const std::wstring store_path = temporary_token_store_path();
	auto now_ms = std::make_shared<std::atomic<std::int64_t>>(1'800'000'000'000LL);
	const auto clock = [now_ms] { return now_ms->load(); };
	ProviderServer server(kTestPort, store_path, kWidgetEventsPort, clock);
	std::string error;
	if (!server.start(error))
		fail(error);

	const auto health = request(server, "GET", "/health", {}, {{"Origin", "http://127.0.0.1:4042"}});
	require(status_code(health) == 200 && response_body(health).find("\"ok\":true") != std::string_view::npos,
		"health endpoint");
	require(status_code(request(server, "GET", "/api/widget-tokens")) == 401, "reject unauthenticated admin request");
	require(status_code(request(server, "GET", "/admin")) == 404, "do not expose a browser admin panel");
	require(status_code(request(server, "GET", "/health", {}, {{"Origin", "https://not-local.example"}})) == 403,
		"reject an untrusted browser origin");
	const auto external_api_preflight = request(
		server, "OPTIONS", "/api/v1/alerts/donations",
		{}, {{"Origin", "https://widget.example"}});
	require(status_code(external_api_preflight) == 204 &&
			external_api_preflight.find("Access-Control-Allow-Origin: https://widget.example") != std::string::npos &&
			external_api_preflight.find("Access-Control-Allow-Headers: Authorization") != std::string::npos,
		"allow browser preflight for scoped API-compatible widget endpoints");
	require(status_code(request(server, "GET", "/api/v1/alerts/donations", {},
				    {{"Origin", "https://widget.example/path"}})) == 403,
		"reject malformed browser origins for API-compatible endpoints");
	require(status_code(request(server, "GET", "/api/widget/events", {}, {}, kWidgetEventsPort)) == 401,
		"reject WebSocket upgrades without an authorized widget token");
	require(status_code(request(server, "GET", "/health", {}, {}, kTestPort, "127.0.0.1:4043")) == 403,
		"reject a mismatched Host header");
	const auto callback = request(server, "GET", "/oauth/callback?code=auth-code-123&state=state-xyz", {},
				      {{"Origin", "null"}});
	require(status_code(callback) == 200, "accept the local OAuth callback");
	const auto callback_data = request(server, "GET", "/api/oauth/callback-code", {},
					   {{"X-Admin-Token", server.admin_token()},
					    {"Origin", "http://127.0.0.1:4042"}});
	require(status_code(callback_data) == 200 &&
			response_body(callback_data).find("\"code\":\"auth-code-123\"") != std::string_view::npos &&
			response_body(callback_data).find("\"state\":\"state-xyz\"") != std::string_view::npos,
		"retrieve the OAuth callback only with admin authentication");

	const auto invalid_scope = request(
		server, "POST", "/api/widget-tokens", "name=test&expiresInMinutes=5&scopes=read%3Aadmin",
		admin_headers(server));
	require(status_code(invalid_scope) == 400, "reject an unsupported token scope");
	const auto invalid_lifetime = request(
		server, "POST", "/api/widget-tokens", "name=test&expiresInMinutes=1441&scopes=read%3Adonation-events",
		admin_headers(server));
	require(status_code(invalid_lifetime) == 400, "reject a token lifetime above 24 hours");
	const auto expired_date = request(
		server, "POST", "/api/widget-tokens",
		"name=test&expiresAt=1799999999999&scopes=read%3Adonation-events", admin_headers(server));
	require(status_code(expired_date) == 400, "reject an expiration date that is not in the future");
	const auto long_expiration = request(
		server, "POST", "/api/widget-tokens",
		"name=long-date&expiresAt=1815763200000&scopes=read%3Adonation-events", admin_headers(server));
	require(status_code(long_expiration) == 201,
		"allow a calendar expiration date beyond the legacy 24-hour duration limit");
	const auto long_expiration_id = json_string_field(response_body(long_expiration), "id");
	require(status_code(request(server, "POST", "/api/widget-tokens/revoke",
				    "id=" + long_expiration_id, admin_headers(server))) == 200,
		"revoke the long-expiration test token");
	const auto invalid_utf8 = request(
		server, "POST", "/api/widget-tokens", "name=%FF&expiresInMinutes=5&scopes=read%3Adonation-events",
		admin_headers(server));
	require(status_code(invalid_utf8) == 400, "reject malformed UTF-8 token names");

	const auto issued = request(
		server, "POST", "/api/widget-tokens",
		"name=%D0%9E%D0%91%D0%A1+test&expiresInMinutes=10&scopes=read%3Adonation-events%2Cread%3Agoal-updates",
		admin_headers(server));
	require(status_code(issued) == 201, "issue a scoped temporary token");
	const auto issued_body = response_body(issued);
	const auto token = json_string_field(issued_body, "token");
	const auto id = json_string_field(issued_body, "id");
	require(issued_body.find("ОБС test") != std::string_view::npos, "preserve UTF-8 token names");
	require(token.size() == 64 && id.size() == 32, "return sufficiently random one-time token and ID");

	SOCKET widget_socket = connect_widget_socket(token);
	const auto initial_stream_status = receive_widget_event(widget_socket);
	require(initial_stream_status.find("\"type\":\"status\"") != std::string::npos &&
			initial_stream_status.find("\"connected\":false") != std::string::npos,
		"send initial realtime status to authorized widget");

	const auto published_profile = request(
		server, "POST", "/api/provider/profile", "{\"id\":123,\"name\":\"Streamer\"}", {},
		kTestPort, "127.0.0.1:4042");
	require(status_code(published_profile) == 401, "reject unauthenticated provider data updates");
	const auto profile_update = request(
		server, "POST", "/api/provider/profile", "{\"id\":123,\"name\":\"Streamer\"}", admin_headers(server));
	require(status_code(profile_update) == 204, "publish the connected account profile");
	const auto compatible_profile = request(
		server, "GET", "/api/v1/user/oauth", {},
		{{"Authorization", "Bearer " + token}, {"Origin", "https://widget.example"}});
	require(status_code(compatible_profile) == 200 &&
			response_body(compatible_profile).find("\"data\":{\"id\":123,\"name\":\"Streamer\"}") !=
				std::string_view::npos &&
			response_body(compatible_profile).find("socket_connection_token") == std::string_view::npos,
		"return the cached profile in DonationAlerts API format without exposing its socket credential");
	require(status_code(request(server, "GET", "/api/v1/user/oauth")) == 401,
		"require the scoped widget credential for DonationAlerts-compatible profile requests");
	const auto compatible_donations = request(
		server, "GET", "/api/v1/alerts/donations?per_page=30", {},
		{{"Authorization", "Bearer " + token}, {"Origin", "http://127.0.0.1:4042"}});
	require(status_code(compatible_donations) == 503,
		"require an active OBS DonationAlerts connection for the API-compatible donation proxy");
	require(status_code(request(server, "GET", "/api/v1/alerts/donations")) == 401,
		"require a scoped widget token for the API-compatible donation proxy");
	require(status_code(request(server, "GET", "/api/v1/alerts/goals", {},
				    {{"Authorization", "Bearer " + token}})) == 404,
		"do not proxy unapproved DonationAlerts API paths");
	const auto proxy_credentials = request(
		server, "POST", "/api/provider/oauth-token", "access_token=test-upstream-token",
		admin_headers(server));
	require(status_code(proxy_credentials) == 204, "store API proxy credentials in memory through admin access");
	const auto rejected_proxy_credentials = request(
		server, "POST", "/api/provider/oauth-token", "access_token=attacker-token",
		{{"Content-Type", "application/x-www-form-urlencoded"}});
	require(status_code(rejected_proxy_credentials) == 401, "protect API proxy credentials with admin authentication");
	require(status_code(request(server, "POST", "/api/provider/oauth-token", "access_token=",
				    admin_headers(server))) == 204,
		"clear in-memory API proxy credentials on disconnect");
	require(status_code(request(server, "GET", "/api/v1/alerts/donations?per_page=30", {},
				    {{"Authorization", "Bearer " + token}})) == 503,
		"stop proxying DonationAlerts requests after clearing the upstream credential");
	const auto donations_update = request(server, "POST", "/api/provider/donations",
					      "[{\"id\":987,\"username\":\"Viewer\",\"amount\":25,\"currency\":\"RUB\"}]",
					      admin_headers(server));
	require(status_code(donations_update) == 204, "publish donation data");
	const auto realtime_status = request(server, "POST", "/api/provider/realtime-status",
					     "{\"type\":\"status\",\"connected\":true,\"message\":\"Connected\"}",
					     admin_headers(server));
	require(status_code(realtime_status) == 204, "publish realtime connection status");
	const auto pushed_status = receive_widget_event(widget_socket);
	require(pushed_status.find("\"type\":\"status\"") != std::string_view::npos &&
			pushed_status.find("\"connected\":true") != std::string_view::npos,
		"notify widgets when the realtime socket connects");
	const auto realtime_event = request(server, "POST", "/api/provider/donation-event",
					    "{\"type\":\"donation\",\"donation\":{\"id\":988,\"amount\":35}}",
					    admin_headers(server));
	require(status_code(realtime_event) == 204, "publish a realtime donation event");
	const auto pushed_event = receive_widget_event(widget_socket);
	require(pushed_event.find("\"type\":\"donation\"") != std::string_view::npos &&
			pushed_event.find("\"id\":988") != std::string_view::npos,
		"deliver a realtime event to the scoped widget WebSocket");
	shutdown(widget_socket, SD_BOTH);
	closesocket(widget_socket);
	const auto widget_data = request(server, "GET", "/api/widget/data", {},
					 {{"Authorization", "Bearer " + token},
					  {"Origin", "http://127.0.0.1:4042"}});
	require(status_code(widget_data) == 200 &&
			response_body(widget_data).find("\"connected\":true") != std::string_view::npos &&
			response_body(widget_data).find("\"name\":\"Streamer\"") != std::string_view::npos &&
			response_body(widget_data).find("\"amount\":25") != std::string_view::npos,
		"allow a scoped widget token to read the provider snapshot");
	require(status_code(request(server, "GET", "/api/widget/data")) == 401,
		"reject widget data requests without a bearer token");
	const auto goal_token_response = request(
		server, "POST", "/api/widget-tokens", "name=goals&expiresInMinutes=10&scopes=read%3Agoal-updates",
		admin_headers(server));
	require(status_code(goal_token_response) == 201, "issue a goal-only token");
	const auto goal_token = json_string_field(response_body(goal_token_response), "token");
	require(status_code(request(server, "GET", "/api/widget/data", {},
				   {{"Authorization", "Bearer " + goal_token}})) == 403,
		"do not expose donation data to a token without donation scope");
	require(status_code(request(server, "POST", "/api/widget-tokens/revoke", "id=" +
							  json_string_field(response_body(goal_token_response), "id"),
					   admin_headers(server))) == 200,
		"revoke the goal-only test token");

	const auto listed = request(server, "GET", "/api/widget-tokens", {},
				    {{"X-Admin-Token", server.admin_token()}, {"Origin", "http://127.0.0.1:4042"}});
	require(status_code(listed) == 200, "list active tokens");
	require(response_body(listed).find(id) != std::string_view::npos, "include token metadata");
	require(response_body(listed).find(token) == std::string_view::npos, "do not reveal issued secrets again");

	const auto revoke_body = "id=" + id;
	const auto revoked = request(server, "POST", "/api/widget-tokens/revoke", revoke_body, admin_headers(server));
	require(status_code(revoked) == 200 && response_body(revoked).find("\"revoked\":true") != std::string_view::npos,
		"revoke token by ID");
	const auto empty_list = request(server, "GET", "/api/widget-tokens", {},
					{{"X-Admin-Token", server.admin_token()}});
	require(status_code(empty_list) == 200 && response_body(empty_list) == "[]", "remove revoked token from the list");

	const auto persistent_issue = request(
		server, "POST", "/api/widget-tokens",
		"name=survives-restart&expiresAt=0&scopes=read%3Adonation-events", admin_headers(server));
	require(status_code(persistent_issue) == 201, "issue token for persistence check");
	const auto persistent_token = json_string_field(response_body(persistent_issue), "token");
	const auto persistent_id = json_string_field(response_body(persistent_issue), "id");
	require(response_body(persistent_issue).find("\"expiresAt\":null") != std::string_view::npos,
		"represent a token without expiration as null");
	server.stop();

	ProviderServer restarted_server(kTestPort, store_path, kWidgetEventsPort, clock);
	if (!restarted_server.start(error))
		fail(error);
	const auto restored_list = request(restarted_server, "GET", "/api/widget-tokens", {},
					   {{"X-Admin-Token", restarted_server.admin_token()}});
	require(status_code(restored_list) == 200 &&
			response_body(restored_list).find(persistent_id) != std::string_view::npos &&
			response_body(restored_list).find("\"expiresAt\":null") != std::string_view::npos &&
			response_body(restored_list).find("\"active\":true") != std::string_view::npos,
		"restore widget token metadata after server restart");
	require(status_code(request(restarted_server, "GET", "/api/widget/data", {},
				    {{"Authorization", "Bearer " + persistent_token}})) == 200,
		"keep the existing widget token usable after server restart");
	SOCKET restored_socket = connect_widget_socket(persistent_token);
	shutdown(restored_socket, SD_BOTH);
	closesocket(restored_socket);

	const auto finite_issue = request(
		restarted_server, "POST", "/api/widget-tokens",
		"name=expires-after-restart&expiresAt=1800000300000&scopes=read%3Adonation-events",
		admin_headers(restarted_server));
	require(status_code(finite_issue) == 201, "issue a token with a configurable expiration");
	const auto finite_token = json_string_field(response_body(finite_issue), "token");
	const auto finite_id = json_string_field(response_body(finite_issue), "id");
	now_ms->fetch_add(6 * 60 * 1000);
	restarted_server.stop();
	ProviderServer expired_server(kTestPort, store_path, kWidgetEventsPort, clock);
	if (!expired_server.start(error))
		fail(error);
	const auto expired_list = request(expired_server, "GET", "/api/widget-tokens", {},
					  {{"X-Admin-Token", expired_server.admin_token()}});
	require(status_code(expired_list) == 200 &&
			response_body(expired_list).find(persistent_id) != std::string_view::npos &&
			response_body(expired_list).find(finite_id) != std::string_view::npos &&
			response_body(expired_list).find("\"active\":false") != std::string_view::npos,
		"restore both non-expiring and expired token metadata after restart");
	require(status_code(request(expired_server, "GET", "/api/widget/data", {},
				    {{"Authorization", "Bearer " + persistent_token}})) == 200,
		"keep a non-expiring token valid after its configured lifetime would have elapsed");
	require(status_code(request(expired_server, "GET", "/api/widget/data", {},
				    {{"Authorization", "Bearer " + finite_token}})) == 401,
		"deny API access to an expired token while retaining its record");
	const auto expired_revoke = request(expired_server, "POST", "/api/widget-tokens/revoke",
					    "id=" + finite_id, admin_headers(expired_server));
	require(status_code(expired_revoke) == 200 &&
			response_body(expired_revoke).find("\"revoked\":true") != std::string_view::npos,
		"revoke an expired token by its saved ID");
	const auto permanent_revoke = request(expired_server, "POST", "/api/widget-tokens/revoke",
					      "id=" + persistent_id, admin_headers(expired_server));
	require(status_code(permanent_revoke) == 200 &&
			response_body(permanent_revoke).find("\"revoked\":true") != std::string_view::npos,
		"revoke a non-expiring token by its saved ID");
	expired_server.stop();

	ProviderServer after_revoke_server(kTestPort, store_path, kWidgetEventsPort, clock);
	if (!after_revoke_server.start(error))
		fail(error);
	const auto after_revoke_list = request(after_revoke_server, "GET", "/api/widget-tokens", {},
					       {{"X-Admin-Token", after_revoke_server.admin_token()}});
	require(status_code(after_revoke_list) == 200 && response_body(after_revoke_list) == "[]",
		"keep revocation persisted across restart");
	after_revoke_server.stop();
	require(DeleteFileW(store_path.c_str()) != 0, "remove temporary token store");

	std::cout << "PASS: local-only binding, CORS/Host checks, admin auth, persistent widget tokens, scopes, and revocation.\n";
	return EXIT_SUCCESS;
}
