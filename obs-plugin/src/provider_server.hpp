#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <thread>

struct HttpRequest;
struct HttpResponse;

class ProviderServer {
public:
	explicit ProviderServer(std::uint16_t port = 4041, std::wstring token_store_path = {},
				std::uint16_t widget_events_port = 4043,
				std::function<std::int64_t()> clock = {});
	~ProviderServer();

	ProviderServer(const ProviderServer &) = delete;
	ProviderServer &operator=(const ProviderServer &) = delete;

	bool start(std::string &error);
	void stop();
	const std::string &admin_token() const;

private:
	struct State;
	enum class WidgetAuthorization { authorized, invalid_token, insufficient_scope };
	std::unique_ptr<State> state_;
	std::uint16_t port_;
	std::uint16_t widget_events_port_;
	std::wstring token_store_path_;
	std::function<std::int64_t()> clock_;
	std::string admin_token_;
	std::atomic<std::uintptr_t> listener_;
	std::atomic<std::uintptr_t> event_listener_;
	std::jthread worker_;
	std::jthread event_worker_;

	void run(std::stop_token stop_token);
	void handle_request(std::uintptr_t client_socket, const HttpRequest &request, std::string_view origin);
	void run_widget_events(std::stop_token stop_token);
	std::string list_widget_tokens();
	bool load_widget_tokens(std::string &error);
	bool persist_widget_tokens(std::string &error) const;
	WidgetAuthorization authorize_widget(const HttpRequest &request, std::string_view required_scope);
	HttpResponse issue_widget_token(std::string_view body);
	HttpResponse revoke_widget_token(std::string_view body);
};
