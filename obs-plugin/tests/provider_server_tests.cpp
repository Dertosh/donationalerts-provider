#include "provider_server.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <cstdlib>
#include <iostream>
#include <map>
#include <string>
#include <string_view>

namespace {

constexpr std::uint16_t kTestPort = 4042;

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

std::map<std::string, std::string, std::less<>> admin_headers(const ProviderServer &server)
{
	return {{"X-Admin-Token", server.admin_token()},
		{"Origin", "http://127.0.0.1:4042"},
		{"Content-Type", "application/x-www-form-urlencoded"}};
}

} // namespace

int main()
{
	ProviderServer server(kTestPort);
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

	const auto published_profile = request(
		server, "POST", "/api/provider/profile", "{\"id\":123,\"name\":\"Streamer\"}", {},
		kTestPort, "127.0.0.1:4042");
	require(status_code(published_profile) == 401, "reject unauthenticated provider data updates");
	const auto profile_update = request(
		server, "POST", "/api/provider/profile", "{\"id\":123,\"name\":\"Streamer\"}", admin_headers(server));
	require(status_code(profile_update) == 204, "publish the connected account profile");
	const auto donations_update = request(server, "POST", "/api/provider/donations",
					      "[{\"id\":987,\"username\":\"Viewer\",\"amount\":25,\"currency\":\"RUB\"}]",
					      admin_headers(server));
	require(status_code(donations_update) == 204, "publish donation data");
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

	server.stop();
	std::cout << "PASS: local-only binding, CORS/Host checks, admin auth, temporary tokens, scope validation, and revocation.\n";
	return EXIT_SUCCESS;
}
