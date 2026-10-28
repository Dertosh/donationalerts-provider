#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <thread>

struct HttpRequest;
struct HttpResponse;

class ProviderServer {
public:
	explicit ProviderServer(std::uint16_t port = 4041);
	~ProviderServer();

	ProviderServer(const ProviderServer &) = delete;
	ProviderServer &operator=(const ProviderServer &) = delete;

	bool start(std::string &error);
	void stop();
	const std::string &admin_token() const;

private:
	struct State;
	std::unique_ptr<State> state_;
	std::uint16_t port_;
	std::string admin_token_;
	std::atomic<std::uintptr_t> listener_;
	std::jthread worker_;

	void run(std::stop_token stop_token);
	void handle_request(std::uintptr_t client_socket, const HttpRequest &request, std::string_view origin);
	std::string list_widget_tokens();
	HttpResponse issue_widget_token(std::string_view body);
	HttpResponse revoke_widget_token(std::string_view body);
};
