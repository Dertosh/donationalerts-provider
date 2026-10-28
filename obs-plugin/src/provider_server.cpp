#include "provider_server.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <cctype>
#include <chrono>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <map>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <sstream>
#include <string_view>
#include <utility>
#include <vector>

struct HttpRequest {
	std::string method;
	std::string target;
	std::string path;
	std::map<std::string, std::string, std::less<>> headers;
	std::string body;
};

struct HttpResponse {
	int status = 200;
	std::string content_type = "application/json; charset=utf-8";
	std::string body;
	std::string extra_headers;
};

namespace {

constexpr std::size_t kMaxRequestBytes = 16 * 1024;
constexpr DWORD kSocketTimeoutMs = 1000;
constexpr std::string_view kAdminHtml = R"html(<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>DonationAlerts OBS Provider</title><style>
body{font:16px system-ui;background:#15171c;color:#eee;max-width:760px;margin:40px auto;padding:0 20px}
input,button{font:inherit;padding:10px;border-radius:6px;border:1px solid #555;background:#22252c;color:#eee}
input[type=text],input[type=password]{width:min(100%,520px);box-sizing:border-box}button{cursor:pointer;background:#7048e8;border:0}
label{display:block;margin:12px 0}.card{background:#20232b;border-radius:10px;padding:20px;margin:18px 0}
small{display:block;color:#aaa;margin:6px 0 12px}.status{min-height:1.5em;color:#9be9a8}.row{display:flex;justify-content:space-between;gap:12px;border-top:1px solid #454851;padding:14px 0}
</style></head><body><h1>DonationAlerts OBS Provider</h1>
<section class="card"><h2>Административный ключ</h2><label>Ключ из журнала OBS
<input id="admin" type="password" autocomplete="off"></label><button id="connect">Подключить</button>
<p id="status" class="status"></p></section>
<section class="card"><h2>Временный ключ виджета</h2><label>Название <input id="name" value="obs-widget" maxlength="80"></label>
<label>Срок действия, минут <input id="lifetime" type="number" min="1" max="1440" value="60"></label>
<label><input type="checkbox" name="scope" value="read:donation-events" checked> События донатов</label>
<label><input type="checkbox" name="scope" value="read:goal-updates"> Обновления целей</label>
<label><input type="checkbox" name="scope" value="read:poll-updates"> Обновления опросов</label>
<button id="issue">Выпустить ключ</button><p id="issued" hidden></p></section>
<section class="card"><h2>Активные ключи</h2><div id="tokens">Подключите панель.</div></section>
<script>
const admin=document.getElementById("admin"),status=document.getElementById("status"),tokens=document.getElementById("tokens");
async function api(path,options={}){const r=await fetch(path,{...options,headers:{"X-Admin-Token":admin.value,...options.headers}});
const data=await r.json();if(!r.ok)throw Error(data.error||`HTTP ${r.status}`);return data}
function say(text){status.textContent=text}
function render(items){tokens.replaceChildren();if(!items.length){tokens.textContent="Нет активных ключей.";return}
for(const t of items){const row=document.createElement("div"),info=document.createElement("div"),name=document.createElement("strong"),small=document.createElement("small"),button=document.createElement("button");
row.className="row";name.textContent=t.name;small.textContent=`Истекает ${new Date(t.expiresAt).toLocaleString()} · ${t.scopes.join(", ")} · ${t.id}`;
button.textContent="Отозвать";button.onclick=async()=>{try{await api("/api/widget-tokens/revoke",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({id:t.id})});await refresh();say("Ключ отозван.")}catch(e){say(e.message)}};
info.append(name,small);row.append(info,button);tokens.append(row)}}
async function refresh(){render(await api("/api/widget-tokens"))}
document.getElementById("connect").onclick=async()=>{try{await refresh();say("Подключено к локальному OBS-плагину.")}catch(e){say(e.message)}};
document.getElementById("issue").onclick=async()=>{try{const scopes=[...document.querySelectorAll('input[name="scope"]:checked')].map(e=>e.value);
const body=new URLSearchParams({name:document.getElementById("name").value,expiresInMinutes:document.getElementById("lifetime").value,scopes:scopes.join(",")});
const result=await api("/api/widget-tokens",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body});
const out=document.getElementById("issued");out.hidden=false;out.replaceChildren(document.createTextNode("Сохраните ключ — повторно он не отображается: "));
const key=document.createElement("input");key.type="text";key.readOnly=true;key.value=result.token;out.append(key);await refresh();say("Временный ключ выпущен.")}catch(e){say(e.message)}};
admin.addEventListener("keydown",e=>{if(e.key==="Enter")document.getElementById("connect").click()});
</script></body></html>)html";

struct WidgetToken {
	std::string id;
	std::string name;
	std::vector<std::string> scopes;
	std::int64_t expires_at_ms;
};

std::string lower_ascii(std::string value)
{
	std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
		return static_cast<char>(std::tolower(ch));
	});
	return value;
}

std::string trim(std::string value)
{
	const auto first = value.find_first_not_of(" \t\r\n");
	if (first == std::string::npos)
		return {};
	const auto last = value.find_last_not_of(" \t\r\n");
	return value.substr(first, last - first + 1);
}

bool valid_utf8(std::string_view value)
{
	for (std::size_t index = 0; index < value.size();) {
		const auto first = static_cast<unsigned char>(value[index]);
		if (first <= 0x7f) {
			++index;
			continue;
		}

		std::size_t count = 0;
		unsigned char second_min = 0x80;
		unsigned char second_max = 0xbf;
		if (first >= 0xc2 && first <= 0xdf) {
			count = 2;
		} else if (first >= 0xe0 && first <= 0xef) {
			count = 3;
			if (first == 0xe0)
				second_min = 0xa0;
			else if (first == 0xed)
				second_max = 0x9f;
		} else if (first >= 0xf0 && first <= 0xf4) {
			count = 4;
			if (first == 0xf0)
				second_min = 0x90;
			else if (first == 0xf4)
				second_max = 0x8f;
		} else {
			return false;
		}

		if (index + count > value.size())
			return false;
		const auto second = static_cast<unsigned char>(value[index + 1]);
		if (second < second_min || second > second_max)
			return false;
		for (std::size_t continuation = 2; continuation < count; ++continuation) {
			const auto byte = static_cast<unsigned char>(value[index + continuation]);
			if (byte < 0x80 || byte > 0xbf)
				return false;
		}
		index += count;
	}
	return true;
}

std::string limit_utf8_characters(std::string_view value, std::size_t limit)
{
	std::size_t index = 0;
	std::size_t characters = 0;
	while (index < value.size() && characters < limit) {
		const auto byte = static_cast<unsigned char>(value[index]);
		const std::size_t count = byte <= 0x7f ? 1 : (byte <= 0xdf ? 2 : (byte <= 0xef ? 3 : 4));
		index += count;
		++characters;
	}
	return std::string(value.substr(0, index));
}

std::string json_escape(std::string_view value)
{
	std::string escaped;
	escaped.reserve(value.size());
	for (const unsigned char ch : value) {
		switch (ch) {
		case '"': escaped += "\\\""; break;
		case '\\': escaped += "\\\\"; break;
		case '\b': escaped += "\\b"; break;
		case '\f': escaped += "\\f"; break;
		case '\n': escaped += "\\n"; break;
		case '\r': escaped += "\\r"; break;
		case '\t': escaped += "\\t"; break;
		default:
			if (ch < 0x20) {
				constexpr char hex[] = "0123456789abcdef";
				escaped += "\\u00";
				escaped += hex[ch >> 4];
				escaped += hex[ch & 0x0f];
			} else {
				escaped += static_cast<char>(ch);
			}
		}
	}
	return escaped;
}

std::string json_error(std::string_view message)
{
	return "{\"error\":\"" + json_escape(message) + "\"}";
}

std::string random_hex(std::size_t bytes)
{
	std::vector<UCHAR> random(bytes);
	if (BCryptGenRandom(nullptr, random.data(), static_cast<ULONG>(random.size()),
			    BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
		throw std::runtime_error("Windows cryptographic random generator failed.");

	constexpr char hex[] = "0123456789abcdef";
	std::string output;
	output.reserve(bytes * 2);
	for (const UCHAR byte : random) {
		output += hex[byte >> 4];
		output += hex[byte & 0x0f];
	}
	return output;
}

std::string sha256_hex(std::string_view input)
{
	BCRYPT_ALG_HANDLE algorithm = nullptr;
	BCRYPT_HASH_HANDLE hash = nullptr;
	std::array<UCHAR, 32> digest{};
	DWORD object_length = 0;
	DWORD bytes_written = 0;
	std::vector<UCHAR> object;
	const auto cleanup = [&] {
		if (hash)
			BCryptDestroyHash(hash);
		if (algorithm)
			BCryptCloseAlgorithmProvider(algorithm, 0);
	};

	if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0)
		throw std::runtime_error("Unable to initialize SHA-256.");
	if (BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_length),
			      sizeof(object_length), &bytes_written, 0) != 0) {
		cleanup();
		throw std::runtime_error("Unable to initialize SHA-256.");
	}
	object.resize(object_length);
	if (BCryptCreateHash(algorithm, &hash, object.data(), object_length, nullptr, 0, 0) != 0 ||
	    BCryptHashData(hash, reinterpret_cast<PUCHAR>(const_cast<char *>(input.data())),
			   static_cast<ULONG>(input.size()), 0) != 0 ||
	    BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) != 0) {
		cleanup();
		throw std::runtime_error("Unable to hash an access token.");
	}
	cleanup();

	constexpr char hex[] = "0123456789abcdef";
	std::string output;
	output.reserve(digest.size() * 2);
	for (const UCHAR byte : digest) {
		output += hex[byte >> 4];
		output += hex[byte & 0x0f];
	}
	return output;
}

bool constant_time_equal(std::string_view left, std::string_view right)
{
	if (left.size() != right.size())
		return false;
	unsigned char difference = 0;
	for (std::size_t index = 0; index < left.size(); ++index)
		difference |= static_cast<unsigned char>(left[index] ^ right[index]);
	return difference == 0;
}

int hex_value(char ch)
{
	if (ch >= '0' && ch <= '9')
		return ch - '0';
	if (ch >= 'a' && ch <= 'f')
		return ch - 'a' + 10;
	if (ch >= 'A' && ch <= 'F')
		return ch - 'A' + 10;
	return -1;
}

std::optional<std::string> url_decode(std::string_view input)
{
	std::string decoded;
	decoded.reserve(input.size());
	for (std::size_t index = 0; index < input.size(); ++index) {
		if (input[index] == '+') {
			decoded += ' ';
		} else if (input[index] == '%') {
			if (index + 2 >= input.size())
				return std::nullopt;
			const int high = hex_value(input[index + 1]);
			const int low = hex_value(input[index + 2]);
			if (high < 0 || low < 0)
				return std::nullopt;
			decoded += static_cast<char>((high << 4) | low);
			index += 2;
		} else {
			decoded += input[index];
		}
	}
	return decoded;
}

std::optional<std::map<std::string, std::string, std::less<>>> parse_form(std::string_view body)
{
	std::map<std::string, std::string, std::less<>> fields;
	while (!body.empty()) {
		const auto separator = body.find('&');
		const auto pair = body.substr(0, separator);
		const auto equal = pair.find('=');
		const auto key = url_decode(pair.substr(0, equal));
		const auto value = url_decode(equal == std::string_view::npos ? std::string_view{} : pair.substr(equal + 1));
		if (!key || !value || key->empty())
			return std::nullopt;
		if (!fields.emplace(*key, *value).second)
			return std::nullopt;
		if (separator == std::string_view::npos)
			break;
		body.remove_prefix(separator + 1);
	}
	return fields;
}

std::optional<std::vector<std::string>> parse_scopes(std::string_view value)
{
	static constexpr std::array<std::string_view, 3> allowed = {
		"read:donation-events", "read:goal-updates", "read:poll-updates"
	};
	if (value.empty())
		return std::nullopt;

	std::vector<std::string> scopes;
	while (!value.empty()) {
		const auto separator = value.find(',');
		const auto scope = trim(std::string(value.substr(0, separator)));
		if (scope.empty() || std::find(allowed.begin(), allowed.end(), scope) == allowed.end() ||
		    std::find(scopes.begin(), scopes.end(), scope) != scopes.end())
			return std::nullopt;
		scopes.push_back(scope);
		if (separator == std::string_view::npos)
			break;
		value.remove_prefix(separator + 1);
	}
	return scopes;
}

std::string scopes_json(const std::vector<std::string> &scopes)
{
	std::string output = "[";
	for (std::size_t index = 0; index < scopes.size(); ++index) {
		if (index)
			output += ',';
		output += '"' + json_escape(scopes[index]) + '"';
	}
	output += ']';
	return output;
}

std::optional<HttpRequest> read_request(SOCKET client)
{
	std::string buffer;
	buffer.reserve(4096);
	std::array<char, 2048> chunk{};
	std::size_t header_end = std::string::npos;
	std::size_t expected_size = 0;

	while (buffer.size() <= kMaxRequestBytes) {
		header_end = buffer.find("\r\n\r\n");
		if (header_end != std::string::npos) {
			if (expected_size == 0) {
				const auto request_line_end = buffer.find("\r\n");
				if (request_line_end == std::string::npos || request_line_end > header_end)
					return std::nullopt;
				const std::string_view headers_text(buffer.data() + request_line_end + 2,
								    header_end - request_line_end - 2);
				std::size_t content_length = 0;
				std::size_t offset = 0;
				while (offset < headers_text.size()) {
					const auto line_end = headers_text.find("\r\n", offset);
					const auto line = headers_text.substr(
						offset, line_end == std::string_view::npos ? line_end : line_end - offset);
					const auto colon = line.find(':');
					if (colon == std::string_view::npos)
						return std::nullopt;
					const auto key = lower_ascii(trim(std::string(line.substr(0, colon))));
					const auto value = trim(std::string(line.substr(colon + 1)));
					if (key == "transfer-encoding")
						return std::nullopt;
					if (key == "content-length") {
						const auto result = std::from_chars(value.data(), value.data() + value.size(),
										    content_length);
						if (result.ec != std::errc{} || result.ptr != value.data() + value.size())
							return std::nullopt;
					}
					if (line_end == std::string_view::npos)
						break;
					offset = line_end + 2;
				}
				if (content_length > kMaxRequestBytes - header_end - 4)
					return std::nullopt;
				expected_size = header_end + 4 + content_length;
			}
			if (buffer.size() >= expected_size)
				break;
		}

		if (buffer.size() == kMaxRequestBytes)
			return std::nullopt;
		const int received = recv(client, chunk.data(), static_cast<int>(chunk.size()), 0);
		if (received <= 0)
			return std::nullopt;
		const auto received_size = static_cast<std::size_t>(received);
		if (received_size > kMaxRequestBytes - buffer.size())
			return std::nullopt;
		buffer.append(chunk.data(), received_size);
	}

	header_end = buffer.find("\r\n\r\n");
	if (header_end == std::string::npos || expected_size == 0 || buffer.size() < expected_size)
		return std::nullopt;

	HttpRequest request;
	const auto request_line_end = buffer.find("\r\n");
	const std::string_view request_line(buffer.data(), request_line_end);
	const auto first_space = request_line.find(' ');
	const auto second_space = request_line.find(' ', first_space == std::string_view::npos ? first_space : first_space + 1);
	if (first_space == std::string_view::npos || second_space == std::string_view::npos ||
	    request_line.substr(second_space + 1) != "HTTP/1.1")
		return std::nullopt;
	request.method = std::string(request_line.substr(0, first_space));
	request.target = std::string(request_line.substr(first_space + 1, second_space - first_space - 1));
	if (request.target.empty() || request.target.front() != '/')
		return std::nullopt;
	const auto query = request.target.find('?');
	request.path = request.target.substr(0, query);
	request.body.assign(buffer.data() + header_end + 4, expected_size - header_end - 4);

	std::size_t offset = request_line_end + 2;
	while (offset < header_end) {
		const auto line_end = buffer.find("\r\n", offset);
		if (line_end == std::string::npos || line_end > header_end)
			return std::nullopt;
		const auto colon = buffer.find(':', offset);
		if (colon == std::string::npos || colon >= line_end)
			return std::nullopt;
		const auto key = lower_ascii(trim(buffer.substr(offset, colon - offset)));
		const auto value = trim(buffer.substr(colon + 1, line_end - colon - 1));
		if (!request.headers.emplace(key, value).second)
			return std::nullopt;
		offset = line_end + 2;
	}
	return request;
}

void send_response(SOCKET client, const HttpResponse &response, std::string_view origin = {})
{
	static const std::map<int, std::string_view> reason = {
		{200, "OK"}, {201, "Created"}, {204, "No Content"}, {400, "Bad Request"},
		{401, "Unauthorized"}, {403, "Forbidden"}, {404, "Not Found"},
		{409, "Conflict"}, {413, "Payload Too Large"}, {415, "Unsupported Media Type"},
		{429, "Too Many Requests"},
		{500, "Internal Server Error"}, {503, "Service Unavailable"}
	};
	const auto found = reason.find(response.status);
	const auto status_text = found == reason.end() ? std::string_view("Error") : found->second;
	std::ostringstream header;
	header << "HTTP/1.1 " << response.status << ' ' << status_text << "\r\n"
	       << "Content-Type: " << response.content_type << "\r\n"
	       << "Content-Length: " << response.body.size() << "\r\n"
	       << "Cache-Control: no-store\r\n"
	       << "Connection: close\r\n"
	       << "X-Content-Type-Options: nosniff\r\n";
	if (!origin.empty())
		header << "Access-Control-Allow-Origin: " << origin << "\r\n"
		       << "Vary: Origin\r\n";
	header << response.extra_headers << "\r\n";

	const std::string header_text = header.str();
	const auto send_all = [client](const char *data, std::size_t size) {
		while (size > 0) {
			const int sent = send(client, data, static_cast<int>(std::min<std::size_t>(size, INT_MAX)), 0);
			if (sent <= 0)
				return;
			data += sent;
			size -= static_cast<std::size_t>(sent);
		}
	};
	send_all(header_text.data(), header_text.size());
	send_all(response.body.data(), response.body.size());
}

std::int64_t current_time_ms()
{
	return std::chrono::duration_cast<std::chrono::milliseconds>(
		       std::chrono::system_clock::now().time_since_epoch())
		.count();
}

} // namespace

struct ProviderServer::State {
	std::mutex mutex;
	std::map<std::string, WidgetToken, std::less<>> tokens;
};

ProviderServer::ProviderServer(std::uint16_t port)
	: state_(std::make_unique<State>()), port_(port), admin_token_(random_hex(32)), listener_(INVALID_SOCKET)
{
}

ProviderServer::~ProviderServer()
{
	stop();
}

const std::string &ProviderServer::admin_token() const
{
	return admin_token_;
}

bool ProviderServer::start(std::string &error)
{
	if (worker_.joinable())
		return true;

	WSADATA winsock_data{};
	const int startup_result = WSAStartup(MAKEWORD(2, 2), &winsock_data);
	if (startup_result != 0) {
		error = "Winsock initialization failed (" + std::to_string(startup_result) + ").";
		return false;
	}

	SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (listener == INVALID_SOCKET) {
		error = "Unable to create the local HTTP listener (Winsock " + std::to_string(WSAGetLastError()) + ").";
		WSACleanup();
		return false;
	}

	sockaddr_in address{};
	address.sin_family = AF_INET;
	address.sin_port = htons(port_);
	address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(listener, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) == SOCKET_ERROR ||
	    listen(listener, SOMAXCONN) == SOCKET_ERROR) {
		const int socket_error = WSAGetLastError();
		closesocket(listener);
		WSACleanup();
		error = "Unable to bind local provider to 127.0.0.1:" + std::to_string(port_) +
			" (Winsock " + std::to_string(socket_error) + ").";
		return false;
	}

	listener_.store(static_cast<std::uintptr_t>(listener));
	worker_ = std::jthread([this](std::stop_token stop_token) { run(stop_token); });
	return true;
}

void ProviderServer::stop()
{
	if (!worker_.joinable())
		return;
	worker_.request_stop();
	worker_.join();
	const SOCKET listener = static_cast<SOCKET>(listener_.exchange(INVALID_SOCKET));
	if (listener != INVALID_SOCKET)
		closesocket(listener);
	WSACleanup();
}

void ProviderServer::run(std::stop_token stop_token)
{
	while (!stop_token.stop_requested()) {
		const SOCKET listener = static_cast<SOCKET>(listener_.load());
		if (listener == INVALID_SOCKET)
			break;
		fd_set read_set;
		FD_ZERO(&read_set);
		FD_SET(listener, &read_set);
		timeval wait_time{0, 250000};
		const int ready = select(0, &read_set, nullptr, nullptr, &wait_time);
		if (ready == 0)
			continue;
		if (ready == SOCKET_ERROR) {
			if (stop_token.stop_requested())
				break;
			continue;
		}
		const SOCKET client = accept(listener, nullptr, nullptr);
		if (client == INVALID_SOCKET) {
			if (stop_token.stop_requested())
				break;
			continue;
		}
		DWORD timeout = kSocketTimeoutMs;
		setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char *>(&timeout), sizeof(timeout));
		setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char *>(&timeout), sizeof(timeout));
		try {
			const auto request = read_request(client);
			if (request) {
				const auto host = request->headers.find("host");
				const auto origin_header = request->headers.find("origin");
				const std::string_view origin = origin_header == request->headers.end() ? std::string_view{} : origin_header->second;
				const auto expected_host = ":" + std::to_string(port_);
				if (host == request->headers.end() ||
				    (host->second != "127.0.0.1" + expected_host && host->second != "localhost" + expected_host)) {
					send_response(client, {403, "application/json; charset=utf-8", json_error("This service only accepts local requests.")});
				} else if (!origin.empty() && origin != "null" &&
					   origin != "http://127.0.0.1" + expected_host && origin != "http://localhost" + expected_host) {
					send_response(client, {403, "application/json; charset=utf-8", json_error("This origin is not allowed.")});
				} else if (request->method == "OPTIONS") {
					send_response(client, {204, "text/plain; charset=utf-8", {},
							       "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
							       "Access-Control-Allow-Headers: Authorization, Content-Type, X-Admin-Token\r\n"},
						      origin);
				} else {
					handle_request(client, *request, origin);
				}
			} else {
				send_response(client, {400, "application/json; charset=utf-8", json_error("Invalid or incomplete HTTP request.")});
			}
		} catch (const std::exception &error) {
			const std::string debug_message = std::string("[DonationAlerts Provider] HTTP handler error: ") +
							  error.what() + "\n";
			OutputDebugStringA(debug_message.c_str());
			send_response(client, {500, "application/json; charset=utf-8", json_error("The provider could not process this request.")});
		}
		shutdown(client, SD_BOTH);
		closesocket(client);
	}
}

void ProviderServer::handle_request(std::uintptr_t client_socket, const HttpRequest &request, std::string_view origin)
{
	const SOCKET client = static_cast<SOCKET>(client_socket);
	if (request.method == "GET" && request.path == "/health") {
		send_response(client, {200, "application/json; charset=utf-8",
				       "{\"ok\":true,\"service\":\"DonationAlerts OBS Provider\",\"donationAlertsConnected\":false}"},
			      origin);
		return;
	}
	if (request.method == "GET" && (request.path == "/admin" || request.path == "/")) {
		send_response(client, {200, "text/html; charset=utf-8", std::string(kAdminHtml),
				       "Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'\r\n"},
			      origin);
		return;
	}
	if (request.path == "/api/widget-tokens") {
		const auto admin_header = request.headers.find("x-admin-token");
		if (admin_header == request.headers.end() || !constant_time_equal(admin_header->second, admin_token_)) {
			send_response(client, {401, "application/json; charset=utf-8", json_error("A valid admin token is required.")}, origin);
			return;
		}
		if (request.method == "GET") {
			send_response(client, {200, "application/json; charset=utf-8", list_widget_tokens()}, origin);
			return;
		}
		if (request.method == "POST") {
			const auto content_type = request.headers.find("content-type");
			const std::string media_type = content_type == request.headers.end()
						       ? std::string{}
						       : lower_ascii(trim(content_type->second.substr(0, content_type->second.find(';'))));
			if (media_type != "application/x-www-form-urlencoded") {
				send_response(client, {415, "application/json; charset=utf-8",
						       json_error("Use application/x-www-form-urlencoded.")}, origin);
				return;
			}
			const auto issued = issue_widget_token(request.body);
			send_response(client, {issued.status, "application/json; charset=utf-8", issued.body}, origin);
			return;
		}
	}
	if (request.method == "POST" && request.path == "/api/widget-tokens/revoke") {
		const auto admin_header = request.headers.find("x-admin-token");
		if (admin_header == request.headers.end() || !constant_time_equal(admin_header->second, admin_token_)) {
			send_response(client, {401, "application/json; charset=utf-8", json_error("A valid admin token is required.")}, origin);
			return;
		}
		const auto revoked = revoke_widget_token(request.body);
		send_response(client, {revoked.status, "application/json; charset=utf-8", revoked.body}, origin);
		return;
	}
	send_response(client, {404, "application/json; charset=utf-8", json_error("Not found.")}, origin);
}

std::string ProviderServer::list_widget_tokens()
{
	std::lock_guard lock(state_->mutex);
	const auto now = current_time_ms();
	std::string output = "[";
	bool first = true;
	for (auto iterator = state_->tokens.begin(); iterator != state_->tokens.end();) {
		if (iterator->second.expires_at_ms <= now) {
			iterator = state_->tokens.erase(iterator);
			continue;
		}
		const auto &token = iterator->second;
		if (!first)
			output += ',';
		first = false;
		output += "{\"id\":\"" + json_escape(token.id) + "\",\"name\":\"" + json_escape(token.name) +
			  "\",\"scopes\":" + scopes_json(token.scopes) + ",\"expiresAt\":" +
			  std::to_string(token.expires_at_ms) + "}";
		++iterator;
	}
	output += ']';
	return output;
}

HttpResponse ProviderServer::issue_widget_token(std::string_view body)
{
	const auto fields = parse_form(body);
	if (!fields)
		return {400, "application/json; charset=utf-8", json_error("Request form is invalid.")};
	const auto name_field = fields->find("name");
	const auto lifetime_field = fields->find("expiresInMinutes");
	const auto scopes_field = fields->find("scopes");
	if (name_field == fields->end() || lifetime_field == fields->end() || scopes_field == fields->end())
		return {400, "application/json; charset=utf-8", json_error("name, expiresInMinutes, and scopes are required.")};
	if (!valid_utf8(name_field->second))
		return {400, "application/json; charset=utf-8", json_error("name must contain valid UTF-8 text.")};

	int lifetime_minutes = 0;
	const auto lifetime = std::from_chars(lifetime_field->second.data(),
					      lifetime_field->second.data() + lifetime_field->second.size(),
					      lifetime_minutes);
	if (lifetime.ec != std::errc{} || lifetime.ptr != lifetime_field->second.data() + lifetime_field->second.size() ||
	    lifetime_minutes < 1 || lifetime_minutes > 1440)
		return {400, "application/json; charset=utf-8", json_error("expiresInMinutes must be between 1 and 1440.")};

	const auto scopes = parse_scopes(scopes_field->second);
	if (!scopes)
		return {400, "application/json; charset=utf-8", json_error("Select one or more valid read-only event scopes.")};

	const std::string token = random_hex(32);
	const std::string id = random_hex(16);
	const std::int64_t expires_at = current_time_ms() + static_cast<std::int64_t>(lifetime_minutes) * 60 * 1000;
	const std::string name = limit_utf8_characters(name_field->second, 80);
	{
		std::lock_guard lock(state_->mutex);
		const auto now = current_time_ms();
		for (auto iterator = state_->tokens.begin(); iterator != state_->tokens.end();) {
			if (iterator->second.expires_at_ms <= now)
				iterator = state_->tokens.erase(iterator);
			else
				++iterator;
		}
		if (state_->tokens.size() >= 500)
			return {429, "application/json; charset=utf-8",
				json_error("The provider has reached its limit of 500 active widget tokens.")};
		state_->tokens.emplace(sha256_hex(token),
				       WidgetToken{id, name.empty() ? "widget" : name, *scopes, expires_at});
	}

	const std::string body_json = "{\"id\":\"" + id + "\",\"name\":\"" + json_escape(name.empty() ? "widget" : name) +
		"\",\"token\":\"" + token + "\",\"scopes\":" + scopes_json(*scopes) +
		",\"expiresAt\":" + std::to_string(expires_at) + "}";
	return {201, "application/json; charset=utf-8", body_json};
}

HttpResponse ProviderServer::revoke_widget_token(std::string_view body)
{
	const auto fields = parse_form(body);
	if (!fields)
		return {400, "application/json; charset=utf-8", json_error("Request form is invalid.")};
	const auto id = fields->find("id");
	if (id == fields->end() || id->second.empty())
		return {400, "application/json; charset=utf-8", json_error("A widget token ID is required.")};

	bool revoked = false;
	{
		std::lock_guard lock(state_->mutex);
		for (auto iterator = state_->tokens.begin(); iterator != state_->tokens.end(); ++iterator) {
			if (iterator->second.id == id->second) {
				state_->tokens.erase(iterator);
				revoked = true;
				break;
			}
		}
	}
	return {200, "application/json; charset=utf-8", revoked ? "{\"revoked\":true}" : "{\"revoked\":false}"};
}
