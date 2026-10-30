#include "provider_server.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <winhttp.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <cctype>
#include <chrono>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <filesystem>
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

constexpr std::size_t kMaxRequestBytes = 256 * 1024;
constexpr std::size_t kMaxWebSocketFrameBytes = 1024 * 1024;
constexpr std::size_t kMaxWidgetEventClients = 32;
constexpr DWORD kSocketTimeoutMs = 1000;
constexpr DWORD kUpstreamTimeoutMs = 10000;
constexpr std::string_view kWebSocketGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
constexpr wchar_t kDonationAlertsApiHost[] = L"www.donationalerts.com";

struct WidgetToken {
	std::string id;
	std::string name;
	std::vector<std::string> scopes;
	std::int64_t expires_at_ms;
};

std::string json_error(std::string_view message);

std::string lower_ascii(std::string value)
{
	std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
		return static_cast<char>(std::tolower(ch));
	});
	return value;
}

std::optional<std::wstring> utf8_to_wide(std::string_view value)
{
	if (value.empty())
		return std::wstring{};
	const int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
					       static_cast<int>(value.size()), nullptr, 0);
	if (length <= 0)
		return std::nullopt;
	std::wstring wide(static_cast<std::size_t>(length), L'\0');
	if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()),
				wide.data(), length) != length)
		return std::nullopt;
	return wide;
}

HttpResponse proxy_donationalerts_get(std::string_view target, std::string_view access_token)
{
	if (target.empty() || target.size() > 4096 ||
	    std::any_of(target.begin(), target.end(), [](unsigned char ch) { return ch <= 0x20 || ch == 0x7f; }))
		return {400, "application/json; charset=utf-8", json_error("The API request target is invalid.")};
	const auto wide_target = utf8_to_wide(target);
	if (!wide_target)
		return {400, "application/json; charset=utf-8", json_error("The API request target is not valid UTF-8.")};

	WinHttpHandle session(WinHttpOpen(L"DonationAlerts OBS Provider/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
					 WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
	if (!session.get())
		return {502, "application/json; charset=utf-8", json_error("Could not initialize the DonationAlerts API proxy.")};
	WinHttpSetTimeouts(session.get(), kUpstreamTimeoutMs, kUpstreamTimeoutMs, kUpstreamTimeoutMs,
			   kUpstreamTimeoutMs);
	WinHttpHandle connection(WinHttpConnect(session.get(), kDonationAlertsApiHost, INTERNET_DEFAULT_HTTPS_PORT, 0));
	if (!connection.get())
		return {502, "application/json; charset=utf-8", json_error("Could not connect to DonationAlerts.")};
	WinHttpHandle request(WinHttpOpenRequest(connection.get(), L"GET", wide_target->c_str(), nullptr,
						 WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE));
	if (!request.get())
		return {502, "application/json; charset=utf-8", json_error("Could not create the DonationAlerts API request.")};

	std::wstring headers = L"Authorization: Bearer ";
	for (const unsigned char ch : access_token)
		headers.push_back(static_cast<wchar_t>(ch));
	headers += L"\r\nAccept: application/json\r\n";
	if (!WinHttpSendRequest(request.get(), headers.c_str(), static_cast<DWORD>(headers.size()),
				WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
	    !WinHttpReceiveResponse(request.get(), nullptr))
		return {502, "application/json; charset=utf-8", json_error("The DonationAlerts API request failed.")};

	DWORD status = 0;
	DWORD status_size = sizeof(status);
	if (!WinHttpQueryHeaders(request.get(), WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
				 WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_size, WINHTTP_NO_HEADER_INDEX))
		return {502, "application/json; charset=utf-8", json_error("Could not read the DonationAlerts API response.")};

	std::string body;
	for (;;) {
		DWORD available = 0;
		if (!WinHttpQueryDataAvailable(request.get(), &available))
			return {502, "application/json; charset=utf-8", json_error("Could not read the DonationAlerts API response.")};
		if (available == 0)
			break;
		if (body.size() + available > 2 * 1024 * 1024)
			return {502, "application/json; charset=utf-8", json_error("The DonationAlerts API response is too large.")};
		const auto offset = body.size();
		body.resize(offset + available);
		DWORD received = 0;
		if (!WinHttpReadData(request.get(), body.data() + offset, available, &received))
			return {502, "application/json; charset=utf-8", json_error("Could not read the DonationAlerts API response.")};
		body.resize(offset + received);
	}
	return {static_cast<int>(status), "application/json; charset=utf-8", std::move(body)};
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

bool valid_widget_origin(std::string_view origin)
{
	if (origin.empty() || origin == "null")
		return true;
	if (origin.size() > 512 ||
	    std::any_of(origin.begin(), origin.end(), [](unsigned char ch) {
		    return ch <= 0x20 || ch == 0x7f || ch == '\\';
	    }))
		return false;
	const auto authority_start = origin.find("://");
	if (authority_start == std::string_view::npos)
		return false;
	const auto scheme = origin.substr(0, authority_start);
	if (scheme != "http" && scheme != "https")
		return false;
	const auto authority = origin.substr(authority_start + 3);
	return !authority.empty() && authority.find_first_of("/?#@") == std::string_view::npos;
}

bool allows_widget_origin(std::string_view path)
{
	return path == "/api/widget/data" || path == "/api/v1/user/oauth" ||
	       path == "/api/v1/alerts/donations";
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
		{401, "Unauthorized"}, {403, "Forbidden"}, {404, "Not Found"}, {405, "Method Not Allowed"},
		{409, "Conflict"}, {413, "Payload Too Large"}, {415, "Unsupported Media Type"},
		{422, "Unprocessable Entity"}, {429, "Too Many Requests"},
		{502, "Bad Gateway"},
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

std::string websocket_accept(std::string_view key)
{
	const std::string input = std::string(key) + std::string(kWebSocketGuid);
	BCRYPT_ALG_HANDLE algorithm = nullptr;
	if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA1_ALGORITHM, nullptr, 0) != 0)
		throw std::runtime_error("Unable to initialize WebSocket handshake hash.");
	BCRYPT_HASH_HANDLE hash = nullptr;
	if (BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0) != 0) {
		BCryptCloseAlgorithmProvider(algorithm, 0);
		throw std::runtime_error("Unable to create WebSocket handshake hash.");
	}
	std::array<UCHAR, 20> digest{};
	const bool success = BCryptHashData(hash, reinterpret_cast<PUCHAR>(const_cast<char *>(input.data())),
					    static_cast<ULONG>(input.size()), 0) == 0 &&
			     BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) == 0;
	BCryptDestroyHash(hash);
	BCryptCloseAlgorithmProvider(algorithm, 0);
	if (!success)
		throw std::runtime_error("Unable to calculate WebSocket handshake hash.");

	DWORD encoded_size = 0;
	if (!CryptBinaryToStringA(digest.data(), static_cast<DWORD>(digest.size()),
				  CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &encoded_size))
		throw std::runtime_error("Unable to encode WebSocket handshake hash.");
	std::string encoded(encoded_size, '\0');
	if (!CryptBinaryToStringA(digest.data(), static_cast<DWORD>(digest.size()),
				  CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, encoded.data(), &encoded_size))
		throw std::runtime_error("Unable to encode WebSocket handshake hash.");
	encoded.resize(encoded_size);
	return encoded;
}

bool websocket_send(SOCKET client, std::uint8_t opcode, std::string_view payload)
{
	std::string frame;
	frame.reserve(payload.size() + 10);
	frame.push_back(static_cast<char>(0x80 | (opcode & 0x0f)));
	if (payload.size() < 126) {
		frame.push_back(static_cast<char>(payload.size()));
	} else if (payload.size() <= std::numeric_limits<std::uint16_t>::max()) {
		frame.push_back(static_cast<char>(126));
		frame.push_back(static_cast<char>((payload.size() >> 8) & 0xff));
		frame.push_back(static_cast<char>(payload.size() & 0xff));
	} else {
		frame.push_back(static_cast<char>(127));
		for (int shift = 56; shift >= 0; shift -= 8)
			frame.push_back(static_cast<char>((static_cast<std::uint64_t>(payload.size()) >> shift) & 0xff));
	}
	frame.append(payload);
	const char *data = frame.data();
	std::size_t remaining = frame.size();
	while (remaining > 0) {
		const int sent = send(client, data, static_cast<int>(std::min<std::size_t>(remaining, INT_MAX)), 0);
		if (sent <= 0)
			return false;
		data += sent;
		remaining -= static_cast<std::size_t>(sent);
	}
	return true;
}

struct WidgetEventClient {
	SOCKET socket = INVALID_SOCKET;
	std::string token_hash;
	std::vector<std::uint8_t> input;
};

bool process_websocket_frames(WidgetEventClient &client)
{
	for (;;) {
		if (client.input.size() < 2)
			return true;
		const auto first = client.input[0];
		const auto second = client.input[1];
		const auto opcode = static_cast<std::uint8_t>(first & 0x0f);
		if ((first & 0x70) != 0)
			return false;
		std::uint64_t payload_size = second & 0x7f;
		std::size_t header_size = 2;
		if (payload_size == 126) {
			if (client.input.size() < 4)
				return true;
			payload_size = (static_cast<std::uint64_t>(client.input[2]) << 8) | client.input[3];
			header_size = 4;
		} else if (payload_size == 127) {
			if (client.input.size() < 10)
				return true;
			payload_size = 0;
			for (std::size_t index = 2; index < 10; ++index)
				payload_size = (payload_size << 8) | client.input[index];
			header_size = 10;
		}
		const bool masked = (second & 0x80) != 0;
		if (!masked || payload_size > kMaxWebSocketFrameBytes)
			return false;
		const std::size_t mask_offset = header_size;
		header_size += 4;
		if (client.input.size() < header_size + payload_size)
			return true;
		if (opcode == 0x8)
			return false;
		if (opcode == 0x9) {
			std::string pong(static_cast<std::size_t>(payload_size), '\0');
			for (std::size_t index = 0; index < payload_size; ++index)
				pong[index] = static_cast<char>(client.input[header_size + index] ^
								client.input[mask_offset + index % 4]);
			if (!websocket_send(client.socket, 0xA, pong))
				return false;
		}
		client.input.erase(client.input.begin(),
				   client.input.begin() + static_cast<std::ptrdiff_t>(header_size + payload_size));
	}
}

void close_event_client(WidgetEventClient &client)
{
	if (client.socket != INVALID_SOCKET) {
		shutdown(client.socket, SD_BOTH);
		closesocket(client.socket);
		client.socket = INVALID_SOCKET;
	}
}

std::int64_t current_time_ms()
{
	return std::chrono::duration_cast<std::chrono::milliseconds>(
		       std::chrono::system_clock::now().time_since_epoch())
		.count();
}

std::wstring default_token_store_path()
{
	const DWORD required = GetEnvironmentVariableW(L"APPDATA", nullptr, 0);
	if (required == 0)
		return {};
	std::wstring appdata(required, L'\0');
	const DWORD written = GetEnvironmentVariableW(L"APPDATA", appdata.data(), required);
	if (written == 0 || written >= required)
		return {};
	appdata.resize(written);
	return (std::filesystem::path(appdata) / L"obs-studio" / L"plugin_config" /
		L"donationalerts-obs-provider-tokens.dat").wstring();
}

void append_u32(std::string &output, std::uint32_t value)
{
	for (unsigned int shift = 0; shift < 32; shift += 8)
		output.push_back(static_cast<char>((value >> shift) & 0xff));
}

void append_u64(std::string &output, std::uint64_t value)
{
	for (unsigned int shift = 0; shift < 64; shift += 8)
		output.push_back(static_cast<char>((value >> shift) & 0xff));
}

bool read_u32(std::string_view input, std::size_t &position, std::uint32_t &value)
{
	if (position > input.size() || input.size() - position < 4)
		return false;
	value = 0;
	for (unsigned int shift = 0; shift < 32; shift += 8)
		value |= static_cast<std::uint32_t>(static_cast<unsigned char>(input[position++])) << shift;
	return true;
}

bool read_u64(std::string_view input, std::size_t &position, std::uint64_t &value)
{
	if (position > input.size() || input.size() - position < 8)
		return false;
	value = 0;
	for (unsigned int shift = 0; shift < 64; shift += 8)
		value |= static_cast<std::uint64_t>(static_cast<unsigned char>(input[position++])) << shift;
	return true;
}

bool append_string(std::string &output, std::string_view value)
{
	if (value.size() > std::numeric_limits<std::uint32_t>::max())
		return false;
	append_u32(output, static_cast<std::uint32_t>(value.size()));
	output.append(value);
	return true;
}

bool read_string(std::string_view input, std::size_t &position, std::string &value, std::size_t max_size)
{
	std::uint32_t size = 0;
	if (!read_u32(input, position, size) || size > max_size || position > input.size() ||
	    input.size() - position < size)
		return false;
	value.assign(input.substr(position, size));
	position += size;
	return true;
}

bool is_hex_string(std::string_view value)
{
	return !value.empty() && std::all_of(value.begin(), value.end(), [](unsigned char ch) {
		return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
	});
}

} // namespace

struct ProviderServer::State {
	std::mutex mutex;
	std::map<std::string, WidgetToken, std::less<>> tokens;
	std::deque<std::string> donation_events;
	std::string realtime_status_json =
		"{\"type\":\"status\",\"connected\":false,\"message\":\"Realtime stream is not connected.\"}";
	std::string oauth_code;
	std::string oauth_state;
	std::string oauth_error;
	std::string upstream_access_token;
	std::string profile_json = "null";
	std::string donations_json = "[]";
};

ProviderServer::ProviderServer(std::uint16_t port, std::wstring token_store_path, std::uint16_t widget_events_port,
			       std::function<std::int64_t()> clock)
	: state_(std::make_unique<State>()), port_(port), widget_events_port_(widget_events_port),
	  token_store_path_(token_store_path.empty() ? default_token_store_path() : std::move(token_store_path)),
	  clock_(clock ? std::move(clock) : std::function<std::int64_t()>(current_time_ms)),
	  admin_token_(random_hex(32)), listener_(INVALID_SOCKET), event_listener_(INVALID_SOCKET)
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
	if (!load_widget_tokens(error))
		return false;

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

	SOCKET event_listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (event_listener == INVALID_SOCKET) {
		const int socket_error = WSAGetLastError();
		closesocket(listener);
		WSACleanup();
		error = "Unable to create the widget WebSocket listener (Winsock " +
			std::to_string(socket_error) + ").";
		return false;
	}
	address.sin_port = htons(widget_events_port_);
	if (bind(event_listener, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) == SOCKET_ERROR ||
	    listen(event_listener, SOMAXCONN) == SOCKET_ERROR) {
		const int socket_error = WSAGetLastError();
		closesocket(event_listener);
		closesocket(listener);
		WSACleanup();
		error = "Unable to bind widget WebSocket to 127.0.0.1:" + std::to_string(widget_events_port_) +
			" (Winsock " + std::to_string(socket_error) + ").";
		return false;
	}

	listener_.store(static_cast<std::uintptr_t>(listener));
	event_listener_.store(static_cast<std::uintptr_t>(event_listener));
	worker_ = std::jthread([this](std::stop_token stop_token) { run(stop_token); });
	event_worker_ = std::jthread([this](std::stop_token stop_token) { run_widget_events(stop_token); });
	return true;
}

void ProviderServer::stop()
{
	if (!worker_.joinable())
		return;
	worker_.request_stop();
	worker_.join();
	event_worker_.request_stop();
	event_worker_.join();
	const SOCKET listener = static_cast<SOCKET>(listener_.exchange(INVALID_SOCKET));
	if (listener != INVALID_SOCKET)
		closesocket(listener);
	const SOCKET event_listener = static_cast<SOCKET>(event_listener_.exchange(INVALID_SOCKET));
	if (event_listener != INVALID_SOCKET)
		closesocket(event_listener);
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
					   origin != "http://127.0.0.1" + expected_host && origin != "http://localhost" + expected_host &&
					   !(allows_widget_origin(request->path) && valid_widget_origin(origin))) {
					send_response(client, {403, "application/json; charset=utf-8", json_error("This origin is not allowed.")});
				} else if (request->method == "OPTIONS") {
					send_response(client, {204, "text/plain; charset=utf-8", {},
							       "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
							       "Access-Control-Allow-Headers: Authorization, Content-Type, X-Admin-Token\r\n"
							       "Access-Control-Allow-Private-Network: true\r\n"},
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

void ProviderServer::run_widget_events(std::stop_token stop_token)
{
	std::vector<WidgetEventClient> clients;
	while (!stop_token.stop_requested()) {
		const SOCKET listener = static_cast<SOCKET>(event_listener_.load());
		if (listener == INVALID_SOCKET)
			break;

		fd_set read_set;
		FD_ZERO(&read_set);
		FD_SET(listener, &read_set);
		for (const auto &client : clients) {
			if (client.socket != INVALID_SOCKET)
				FD_SET(client.socket, &read_set);
		}
		timeval wait_time{0, 250000};
		const int ready = select(0, &read_set, nullptr, nullptr, &wait_time);
		if (ready == SOCKET_ERROR) {
			if (stop_token.stop_requested())
				break;
			continue;
		}

		if (ready > 0 && FD_ISSET(listener, &read_set)) {
			const SOCKET socket = accept(listener, nullptr, nullptr);
			if (socket != INVALID_SOCKET) {
				if (clients.size() >= kMaxWidgetEventClients) {
					send_response(socket, {503, "application/json; charset=utf-8",
							       json_error("The widget WebSocket connection limit was reached.")});
					shutdown(socket, SD_BOTH);
					closesocket(socket);
					continue;
				}
				DWORD timeout = kSocketTimeoutMs;
				setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char *>(&timeout),
					   sizeof(timeout));
				setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char *>(&timeout),
					   sizeof(timeout));
				try {
					const auto request = read_request(socket);
					if (request) {
						const auto host = request->headers.find("host");
						const auto origin_header = request->headers.find("origin");
						const auto key_header = request->headers.find("sec-websocket-key");
						const auto upgrade_header = request->headers.find("upgrade");
						const auto version_header = request->headers.find("sec-websocket-version");
						const auto protocol_header = request->headers.find("sec-websocket-protocol");
						const std::string_view origin =
							origin_header == request->headers.end() ? std::string_view{} : origin_header->second;
						const bool valid_host =
							host != request->headers.end() &&
							(host->second == "127.0.0.1:" + std::to_string(widget_events_port_) ||
							 host->second == "localhost:" + std::to_string(widget_events_port_));
						const bool valid_origin = valid_widget_origin(origin);
						const bool valid_upgrade = upgrade_header != request->headers.end() &&
							lower_ascii(trim(upgrade_header->second)) == "websocket" &&
							version_header != request->headers.end() && version_header->second == "13" &&
							key_header != request->headers.end() && !key_header->second.empty();
						std::string widget_token;
						if (protocol_header != request->headers.end()) {
							std::istringstream protocols(protocol_header->second);
							std::string protocol;
							std::getline(protocols, protocol, ',');
							std::string token;
							std::getline(protocols, token, ',');
							if (trim(protocol) == "donationalerts-widget-v1")
								widget_token = trim(token);
						}
						const bool has_token = !widget_token.empty();
						HttpRequest auth_request;
						if (has_token)
							auth_request.headers.emplace("authorization", "Bearer " + widget_token);
						const bool valid_request = request->method == "GET" &&
							request->path == "/api/widget/events" && valid_host && valid_origin &&
							valid_upgrade && has_token &&
							authorize_widget(auth_request, "read:donation-events") ==
								WidgetAuthorization::authorized;
						if (valid_request) {
							const auto accept_key = websocket_accept(key_header->second);
							const std::string handshake =
								"HTTP/1.1 101 Switching Protocols\r\n"
								"Upgrade: websocket\r\n"
								"Connection: Upgrade\r\n"
								"Sec-WebSocket-Protocol: donationalerts-widget-v1\r\n"
								"Sec-WebSocket-Accept: " + accept_key + "\r\n\r\n";
							const char *data = handshake.data();
							std::size_t remaining = handshake.size();
							while (remaining > 0) {
								const int sent = send(socket, data,
									static_cast<int>(std::min<std::size_t>(remaining, INT_MAX)), 0);
								if (sent <= 0)
									break;
								data += sent;
								remaining -= static_cast<std::size_t>(sent);
							}
							std::string realtime_status;
							{
								std::lock_guard lock(state_->mutex);
								realtime_status = state_->realtime_status_json;
							}
							if (remaining == 0 && websocket_send(socket, 0x1, realtime_status)) {
								u_long non_blocking = 1;
								if (ioctlsocket(socket, FIONBIO, &non_blocking) == 0) {
									clients.push_back({socket, sha256_hex(widget_token), {}});
									continue;
								}
							}
						} else {
							const int status = valid_host && valid_origin ? 401 : 403;
							send_response(socket, {status, "application/json; charset=utf-8",
								json_error(status == 401 ? "A valid donation widget token is required."
											 : "This WebSocket request is not allowed.")});
						}
					}
				} catch (const std::exception &error) {
					const std::string debug_message =
						std::string("[DonationAlerts Provider] WebSocket handshake error: ") + error.what() + "\n";
					OutputDebugStringA(debug_message.c_str());
				}
				shutdown(socket, SD_BOTH);
				closesocket(socket);
			}
		}

		for (std::size_t index = 0; index < clients.size();) {
			auto &client = clients[index];
			bool keep = client.socket != INVALID_SOCKET;
			if (keep && ready > 0 && FD_ISSET(client.socket, &read_set)) {
				std::array<std::uint8_t, 4096> incoming{};
				const int received = recv(client.socket, reinterpret_cast<char *>(incoming.data()),
							  static_cast<int>(incoming.size()), 0);
				if (received <= 0) {
					keep = false;
				} else {
					client.input.insert(client.input.end(), incoming.begin(),
							    incoming.begin() + received);
					keep = process_websocket_frames(client);
				}
			}
			if (!keep) {
				close_event_client(client);
				clients.erase(clients.begin() + static_cast<std::ptrdiff_t>(index));
			} else {
				++index;
			}
		}

		std::deque<std::string> events;
		{
			std::lock_guard lock(state_->mutex);
			events.swap(state_->donation_events);
		}
		for (const auto &event : events) {
			for (std::size_t index = 0; index < clients.size();) {
				auto &client = clients[index];
				bool authorized = false;
				{
					std::lock_guard lock(state_->mutex);
					const auto token = state_->tokens.find(client.token_hash);
					authorized = token != state_->tokens.end() &&
						(token->second.expires_at_ms == 0 || token->second.expires_at_ms > clock_()) &&
						std::find(token->second.scopes.begin(), token->second.scopes.end(),
							  "read:donation-events") != token->second.scopes.end();
				}
				if (!authorized || !websocket_send(client.socket, 0x1, event)) {
					close_event_client(client);
					clients.erase(clients.begin() + static_cast<std::ptrdiff_t>(index));
				} else {
					++index;
				}
			}
		}
	}

	for (auto &client : clients)
		close_event_client(client);
}

void ProviderServer::handle_request(std::uintptr_t client_socket, const HttpRequest &request, std::string_view origin)
{
	const SOCKET client = static_cast<SOCKET>(client_socket);
	if (request.method == "GET" && request.path == "/oauth/callback") {
		const auto query_start = request.target.find('?');
		if (query_start == std::string::npos) {
			send_response(client, {400, "text/plain; charset=utf-8", "Missing OAuth callback parameters."});
			return;
		}
		const auto fields = parse_form(std::string_view(request.target).substr(query_start + 1));
		if (!fields) {
			send_response(client, {400, "text/plain; charset=utf-8", "Invalid OAuth callback parameters."});
			return;
		}
		const auto code = fields->find("code");
		const auto state = fields->find("state");
		const auto error = fields->find("error");
		if ((code == fields->end() || code->second.empty()) && error == fields->end()) {
			send_response(client, {400, "text/plain; charset=utf-8", "Authorization code was not provided."});
			return;
		}
		if ((code != fields->end() && code->second.size() > 4096) ||
		    (state != fields->end() && state->second.size() > 256) ||
		    (error != fields->end() && error->second.size() > 256)) {
			send_response(client, {400, "text/plain; charset=utf-8", "OAuth callback parameters are too large."});
			return;
		}
		{
			std::lock_guard lock(state_->mutex);
			state_->oauth_code = code == fields->end() ? std::string{} : code->second;
			state_->oauth_state = state == fields->end() ? std::string{} : state->second;
			state_->oauth_error = error == fields->end() ? std::string{} : error->second;
		}
		send_response(client, {200, "text/html; charset=utf-8",
				       "<!doctype html><meta charset=utf-8><title>OBS</title>"
				       "<p>Authorization received. Return to OBS.</p>",
				       "Content-Security-Policy: default-src 'none'; base-uri 'none'\r\n"});
		return;
	}

	if (request.method == "GET" && request.path == "/health") {
		bool connected = false;
		{
			std::lock_guard lock(state_->mutex);
			connected = state_->profile_json != "null";
		}
		send_response(client, {200, "application/json; charset=utf-8",
				       "{\"ok\":true,\"service\":\"DonationAlerts OBS Provider\",\"donationAlertsConnected\":" +
					       std::string(connected ? "true}" : "false}")},
			      origin);
		return;
	}

	if (request.path == "/api/oauth/callback-code") {
		const auto admin_header = request.headers.find("x-admin-token");
		if (admin_header == request.headers.end() || !constant_time_equal(admin_header->second, admin_token_)) {
			send_response(client, {401, "application/json; charset=utf-8", json_error("A valid admin token is required.")},
				      origin);
			return;
		}
		if (request.method == "GET") {
			std::string response;
			{
				std::lock_guard lock(state_->mutex);
				response = "{\"code\":\"" + json_escape(state_->oauth_code) + "\",\"state\":\"" +
					   json_escape(state_->oauth_state) + "\",\"error\":\"" +
					   json_escape(state_->oauth_error) + "\"}";
				state_->oauth_code.clear();
				state_->oauth_state.clear();
				state_->oauth_error.clear();
			}
			send_response(client, {200, "application/json; charset=utf-8", std::move(response)}, origin);
			return;
		}
	}

	if (request.path == "/api/provider/oauth-token") {
		const auto admin_header = request.headers.find("x-admin-token");
		if (admin_header == request.headers.end() || !constant_time_equal(admin_header->second, admin_token_)) {
			send_response(client, {401, "application/json; charset=utf-8", json_error("A valid admin token is required.")},
				      origin);
			return;
		}
		if (request.method != "POST") {
			send_response(client, {405, "application/json; charset=utf-8", json_error("Use POST to update the OAuth token.")},
				      origin);
			return;
		}
		const auto fields = parse_form(request.body);
		if (!fields) {
			send_response(client, {400, "application/json; charset=utf-8", json_error("A valid access_token field is required.")},
				      origin);
			return;
		}
		const auto access_token = fields->find("access_token");
		if (access_token == fields->end() || access_token->second.size() > 4096 ||
		    std::any_of(access_token->second.begin(), access_token->second.end(), [](unsigned char ch) {
			    return ch < 0x20 || ch == 0x7f;
		    })) {
			send_response(client, {400, "application/json; charset=utf-8", json_error("A valid access_token field is required.")},
				      origin);
			return;
		}
		{
			std::lock_guard lock(state_->mutex);
			state_->upstream_access_token = access_token->second;
		}
		send_response(client, {204, "application/json; charset=utf-8", {}}, origin);
		return;
	}

	if (request.path == "/api/provider/profile" || request.path == "/api/provider/donations" ||
	    request.path == "/api/provider/donation-event" || request.path == "/api/provider/realtime-status") {
		const auto admin_header = request.headers.find("x-admin-token");
		if (admin_header == request.headers.end() || !constant_time_equal(admin_header->second, admin_token_)) {
			send_response(client, {401, "application/json; charset=utf-8", json_error("A valid admin token is required.")},
				      origin);
			return;
		}
		if (request.method == "POST") {
			const bool profile = request.path == "/api/provider/profile";
			const bool event = request.path == "/api/provider/donation-event";
			const bool realtime_status = request.path == "/api/provider/realtime-status";
			const bool valid_shape = profile ? (request.body == "null" ||
								 (request.body.size() >= 2 && request.body.front() == '{' &&
								  request.body.back() == '}'))
							 : (event || realtime_status)
								   ? (request.body.size() >= 2 && request.body.front() == '{' &&
								      request.body.back() == '}')
								   : (request.body.size() >= 2 && request.body.front() == '[' &&
								      request.body.back() == ']');
			if (!valid_shape) {
				send_response(client, {400, "application/json; charset=utf-8", json_error("Invalid provider data.")},
					      origin);
				return;
			}
			{
				std::lock_guard lock(state_->mutex);
				if (profile)
					state_->profile_json = request.body;
				else if (event)
					state_->donation_events.push_back(request.body);
				else if (realtime_status) {
					state_->realtime_status_json = request.body;
					state_->donation_events.push_back(request.body);
				}
				else
					state_->donations_json = request.body;
			}
			send_response(client, {204, "application/json; charset=utf-8", {}}, origin);
			return;
		}
	}

	if (request.method == "GET" && request.path == "/api/widget/data") {
		const auto authorization_header = request.headers.find("authorization");
		if (authorization_header == request.headers.end() ||
		    !authorization_header->second.starts_with("Bearer ")) {
			send_response(client, {401, "application/json; charset=utf-8", json_error("A widget bearer token is required.")},
				      origin);
			return;
		}
		const auto authorization = authorize_widget(request, "read:donation-events");
		if (authorization != WidgetAuthorization::authorized) {
			const bool invalid_token = authorization == WidgetAuthorization::invalid_token;
			send_response(client, {invalid_token ? 401 : 403, "application/json; charset=utf-8",
					       json_error(invalid_token
								  ? "A valid, unexpired widget token is required."
								  : "This widget token does not have the donation-events scope.")},
				      origin);
			return;
		}
		{
			std::lock_guard lock(state_->mutex);
			const std::string response = "{\"connected\":" +
				std::string(state_->profile_json == "null" ? "false" : "true") +
				",\"profile\":" + state_->profile_json + ",\"donations\":" + state_->donations_json +
				",\"goals\":[],\"polls\":[]}";
			send_response(client, {200, "application/json; charset=utf-8", response}, origin);
		}
		return;
	}

	if (request.method == "GET" &&
	    (request.path == "/api/v1/user/oauth" || request.path == "/api/v1/alerts/donations")) {
		const auto authorization = authorize_widget(request, "read:donation-events");
		if (authorization != WidgetAuthorization::authorized) {
			const bool invalid_token = authorization == WidgetAuthorization::invalid_token;
			send_response(client, {invalid_token ? 401 : 403, "application/json; charset=utf-8",
					       json_error(invalid_token
								  ? "A valid, unexpired widget token is required."
								  : "This widget token does not have the donation-events scope.")},
				      origin);
			return;
		}
		if (request.path == "/api/v1/user/oauth") {
			std::string profile;
			{
				std::lock_guard lock(state_->mutex);
				profile = state_->profile_json;
			}
			if (profile == "null") {
				send_response(client, {503, "application/json; charset=utf-8",
						       json_error("DonationAlerts account is not connected in OBS.")},
					      origin);
				return;
			}
			send_response(client, {200, "application/json; charset=utf-8",
					       "{\"data\":" + profile + "}"},
				      origin);
			return;
		}

		std::string access_token;
		{
			std::lock_guard lock(state_->mutex);
			access_token = state_->upstream_access_token;
		}
		if (access_token.empty()) {
			send_response(client, {503, "application/json; charset=utf-8",
					       json_error("DonationAlerts account is not connected in OBS.")},
				      origin);
			return;
		}
		const auto proxied = proxy_donationalerts_get(request.target, access_token);
		send_response(client, proxied, origin);
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

ProviderServer::WidgetAuthorization ProviderServer::authorize_widget(const HttpRequest &request,
								     std::string_view required_scope)
{
	const auto authorization = request.headers.find("authorization");
	if (authorization == request.headers.end() || !authorization->second.starts_with("Bearer "))
		return WidgetAuthorization::invalid_token;
	const auto token = std::string_view(authorization->second).substr(7);
	if (token.empty())
		return WidgetAuthorization::invalid_token;

	std::lock_guard lock(state_->mutex);
	const auto found = state_->tokens.find(sha256_hex(token));
	if (found == state_->tokens.end() ||
	    (found->second.expires_at_ms != 0 && found->second.expires_at_ms <= clock_()))
		return WidgetAuthorization::invalid_token;
	return std::find(found->second.scopes.begin(), found->second.scopes.end(), required_scope) !=
			       found->second.scopes.end()
		       ? WidgetAuthorization::authorized
		       : WidgetAuthorization::insufficient_scope;
}

std::string ProviderServer::list_widget_tokens()
{
	std::lock_guard lock(state_->mutex);
	const auto now = clock_();
	std::string output = "[";
	bool first = true;
	for (const auto &entry : state_->tokens) {
		const auto &token = entry.second;
		if (!first)
			output += ',';
		first = false;
		output += "{\"id\":\"" + json_escape(token.id) + "\",\"name\":\"" + json_escape(token.name) +
			  "\",\"scopes\":" + scopes_json(token.scopes) + ",\"expiresAt\":" +
			  (token.expires_at_ms == 0 ? "null" : std::to_string(token.expires_at_ms)) +
			  ",\"active\":" +
			  (token.expires_at_ms == 0 || token.expires_at_ms > now ? "true" : "false") + "}";
	}
	output += ']';
	return output;
}

bool ProviderServer::load_widget_tokens(std::string &error)
{
	if (token_store_path_.empty()) {
		error = "The widget token storage path is unavailable (APPDATA is not set).";
		return false;
	}

	HANDLE file = CreateFileW(token_store_path_.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
				  FILE_ATTRIBUTE_NORMAL, nullptr);
	if (file == INVALID_HANDLE_VALUE) {
		const DWORD code = GetLastError();
		if (code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND)
			return true;
		error = "Unable to open the widget token store (Windows " + std::to_string(code) + ").";
		return false;
	}

	LARGE_INTEGER size{};
	if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 || size.QuadPart > 1024 * 1024) {
		const DWORD code = GetLastError();
		CloseHandle(file);
		error = "The widget token store has an invalid size (Windows " + std::to_string(code) + ").";
		return false;
	}

	std::string encrypted(static_cast<std::size_t>(size.QuadPart), '\0');
	DWORD bytes_read = 0;
	const BOOL read_ok = ReadFile(file, encrypted.data(), static_cast<DWORD>(encrypted.size()), &bytes_read, nullptr);
	CloseHandle(file);
	if (!read_ok || bytes_read != encrypted.size()) {
		error = "Unable to read the widget token store (Windows " + std::to_string(GetLastError()) + ").";
		return false;
	}

	DATA_BLOB input{static_cast<DWORD>(encrypted.size()), reinterpret_cast<BYTE *>(encrypted.data())};
	DATA_BLOB output{};
	if (!CryptUnprotectData(&input, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &output)) {
		error = "Unable to decrypt the widget token store (Windows " + std::to_string(GetLastError()) + ").";
		return false;
	}
	std::string plaintext(reinterpret_cast<const char *>(output.pbData), output.cbData);
	LocalFree(output.pbData);

	static constexpr std::string_view magic = "DAWTOK1";
	if (plaintext.size() < magic.size() + 4 || plaintext.substr(0, magic.size()) != magic) {
		error = "The widget token store has an unsupported or corrupted format.";
		return false;
	}
	std::size_t position = magic.size();
	std::uint32_t count = 0;
	if (!read_u32(plaintext, position, count) || count > 500) {
		error = "The widget token store contains an invalid token count.";
		return false;
	}

	std::map<std::string, WidgetToken, std::less<>> loaded_tokens;
	for (std::uint32_t index = 0; index < count; ++index) {
		std::string hash;
		std::string id;
		std::uint64_t expires_at = 0;
		std::string name;
		std::uint32_t scope_count = 0;
		if (!read_string(plaintext, position, hash, 64) || hash.size() != 64 || !is_hex_string(hash) ||
		    !read_string(plaintext, position, id, 32) || id.size() != 32 || !is_hex_string(id) ||
		    !read_u64(plaintext, position, expires_at) ||
		    expires_at > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()) ||
		    !read_string(plaintext, position, name, 320) ||
		    !valid_utf8(name) || !read_u32(plaintext, position, scope_count) || scope_count == 0 || scope_count > 3) {
			error = "The widget token store contains invalid token metadata.";
			return false;
		}

		std::vector<std::string> scopes;
		std::string scope_list;
		for (std::uint32_t scope_index = 0; scope_index < scope_count; ++scope_index) {
			std::string scope;
			if (!read_string(plaintext, position, scope, 64)) {
				error = "The widget token store contains invalid scopes.";
				return false;
			}
			if (!scope_list.empty())
				scope_list += ',';
			scope_list += scope;
			scopes.push_back(std::move(scope));
		}
		const auto validated_scopes = parse_scopes(scope_list);
		if (!validated_scopes || *validated_scopes != scopes) {
			error = "The widget token store contains unsupported scopes.";
			return false;
		}
		const auto inserted =
			loaded_tokens.emplace(std::move(hash),
					      WidgetToken{std::move(id), std::move(name), std::move(scopes),
							  static_cast<std::int64_t>(expires_at)}).second;
		if (!inserted) {
			error = "The widget token store contains duplicate entries.";
			return false;
		}
	}
	if (position != plaintext.size()) {
		error = "The widget token store contains unexpected trailing data.";
		return false;
	}
	state_->tokens = std::move(loaded_tokens);
	return true;
}

bool ProviderServer::persist_widget_tokens(std::string &error) const
{
	if (token_store_path_.empty()) {
		error = "The widget token storage path is unavailable (APPDATA is not set).";
		return false;
	}

	std::string plaintext = "DAWTOK1";
	if (state_->tokens.size() > 500) {
		error = "The widget token store exceeds its maximum supported token count.";
		return false;
	}
	append_u32(plaintext, static_cast<std::uint32_t>(state_->tokens.size()));
	for (const auto &[hash, token] : state_->tokens) {
		if (!append_string(plaintext, hash) || !append_string(plaintext, token.id)) {
			error = "The widget token metadata is too large to store.";
			return false;
		}
		append_u64(plaintext, static_cast<std::uint64_t>(token.expires_at_ms));
		if (!append_string(plaintext, token.name)) {
			error = "The widget token metadata is too large to store.";
			return false;
		}
		append_u32(plaintext, static_cast<std::uint32_t>(token.scopes.size()));
		for (const auto &scope : token.scopes) {
			if (!append_string(plaintext, scope)) {
				error = "The widget token scope is too large to store.";
				return false;
			}
		}
	}
	if (plaintext.size() > 1024 * 1024) {
		error = "The widget token store exceeds its maximum supported size.";
		return false;
	}

	DATA_BLOB input{static_cast<DWORD>(plaintext.size()), reinterpret_cast<BYTE *>(plaintext.data())};
	DATA_BLOB output{};
	if (!CryptProtectData(&input, L"DonationAlerts OBS Provider widget tokens", nullptr, nullptr, nullptr,
			      CRYPTPROTECT_UI_FORBIDDEN, &output)) {
		error = "Unable to encrypt the widget token store (Windows " + std::to_string(GetLastError()) + ").";
		return false;
	}
	const std::string encrypted(reinterpret_cast<const char *>(output.pbData), output.cbData);
	LocalFree(output.pbData);

	const std::filesystem::path destination(token_store_path_);
	std::error_code filesystem_error;
	std::filesystem::create_directories(destination.parent_path(), filesystem_error);
	if (filesystem_error) {
		error = "Unable to create the widget token storage directory (Windows " +
			std::to_string(static_cast<unsigned long>(filesystem_error.value())) + ").";
		return false;
	}
	const std::wstring temporary_path = token_store_path_ + L".tmp";
	HANDLE file = CreateFileW(temporary_path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
				  FILE_ATTRIBUTE_NORMAL, nullptr);
	if (file == INVALID_HANDLE_VALUE) {
		error = "Unable to create the widget token store (Windows " + std::to_string(GetLastError()) + ").";
		return false;
	}

	DWORD bytes_written = 0;
	const BOOL write_ok = WriteFile(file, encrypted.data(), static_cast<DWORD>(encrypted.size()), &bytes_written, nullptr);
	const BOOL flush_ok = write_ok && bytes_written == encrypted.size() && FlushFileBuffers(file);
	const DWORD write_error = flush_ok ? ERROR_SUCCESS : GetLastError();
	CloseHandle(file);
	if (!flush_ok || !MoveFileExW(temporary_path.c_str(), token_store_path_.c_str(),
				      MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
		const DWORD code = flush_ok ? GetLastError() : write_error;
		DeleteFileW(temporary_path.c_str());
		error = "Unable to save the widget token store (Windows " + std::to_string(code) + ").";
		return false;
	}
	return true;
}

HttpResponse ProviderServer::issue_widget_token(std::string_view body)
{
	const auto fields = parse_form(body);
	if (!fields)
		return {400, "application/json; charset=utf-8", json_error("Request form is invalid.")};
	const auto name_field = fields->find("name");
	const auto lifetime_field = fields->find("expiresInMinutes");
	const auto expiration_field = fields->find("expiresAt");
	const auto scopes_field = fields->find("scopes");
	if (name_field == fields->end() ||
	    (lifetime_field == fields->end() && expiration_field == fields->end()) ||
	    scopes_field == fields->end())
		return {400, "application/json; charset=utf-8",
			json_error("name, expiresAt (or legacy expiresInMinutes), and scopes are required.")};
	if (!valid_utf8(name_field->second))
		return {400, "application/json; charset=utf-8", json_error("name must contain valid UTF-8 text.")};

	std::int64_t expires_at = 0;
	if (expiration_field != fields->end()) {
		const auto expiration =
			std::from_chars(expiration_field->second.data(),
					expiration_field->second.data() + expiration_field->second.size(), expires_at);
		if (expiration.ec != std::errc{} ||
		    expiration.ptr != expiration_field->second.data() + expiration_field->second.size() ||
		    expires_at < 0 || (expires_at != 0 && expires_at <= clock_()))
			return {400, "application/json; charset=utf-8",
				json_error("expiresAt must be 0 (no expiration) or a future Unix timestamp in milliseconds.")};
	} else {
		int lifetime_minutes = 0;
		const auto lifetime = std::from_chars(lifetime_field->second.data(),
						      lifetime_field->second.data() + lifetime_field->second.size(),
						      lifetime_minutes);
		if (lifetime.ec != std::errc{} ||
		    lifetime.ptr != lifetime_field->second.data() + lifetime_field->second.size() ||
		    lifetime_minutes < 0 || lifetime_minutes > 1440)
			return {400, "application/json; charset=utf-8",
				json_error("Legacy expiresInMinutes must be 0 (no expiration) or between 1 and 1440.")};
		expires_at = lifetime_minutes == 0
				     ? 0
				     : clock_() + static_cast<std::int64_t>(lifetime_minutes) * 60 * 1000;
	}

	const auto scopes = parse_scopes(scopes_field->second);
	if (!scopes)
		return {400, "application/json; charset=utf-8", json_error("Select one or more valid read-only event scopes.")};

	const std::string token = random_hex(32);
	const std::string id = random_hex(16);
	const std::string name = limit_utf8_characters(name_field->second, 80);
	{
		std::lock_guard lock(state_->mutex);
		if (state_->tokens.size() >= 500)
			return {429, "application/json; charset=utf-8",
				json_error("The provider has reached its limit of 500 stored widget token records. Revoke unused tokens to issue another.")};
		const std::string token_hash = sha256_hex(token);
		state_->tokens.emplace(token_hash, WidgetToken{id, name.empty() ? "widget" : name, *scopes, expires_at});
		std::string storage_error;
		if (!persist_widget_tokens(storage_error)) {
			state_->tokens.erase(token_hash);
			return {500, "application/json; charset=utf-8", json_error(storage_error)};
		}
	}

	const std::string body_json = "{\"id\":\"" + id + "\",\"name\":\"" + json_escape(name.empty() ? "widget" : name) +
		"\",\"token\":\"" + token + "\",\"scopes\":" + scopes_json(*scopes) +
		",\"expiresAt\":" + (expires_at == 0 ? "null" : std::to_string(expires_at)) + "}";
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
				const auto token_hash = iterator->first;
				const auto token = iterator->second;
				state_->tokens.erase(iterator);
				std::string storage_error;
				if (!persist_widget_tokens(storage_error)) {
					state_->tokens.emplace(token_hash, token);
					return {500, "application/json; charset=utf-8", json_error(storage_error)};
				}
				revoked = true;
				break;
			}
		}
	}
	return {200, "application/json; charset=utf-8", revoked ? "{\"revoked\":true}" : "{\"revoked\":false}"};
}
