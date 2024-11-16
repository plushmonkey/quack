#pragma once

#include <quack/types.h>
#include <quack/utility.h>

#include <string_view>

namespace quack {
namespace http {

enum class RequestError { Success, Memory, InvalidLine, BadMethod, BadURI, BadVersion };

struct Request {
  std::string_view method;
  std::string_view uri;
  std::string_view version;
  size_t line_size = 0;
};

constexpr size_t kMaxHeaderFields = 64;
struct HeaderKeyValue {
  std::string_view key;
  std::string_view value;
};

struct Header {
  Request request;
  size_t field_count = 0;
  HeaderKeyValue fields[kMaxHeaderFields];

  inline std::optional<std::string_view> GetField(std::string_view key) const {
    key = trim(key);

    for (size_t i = 0; i < field_count; ++i) {
      if (key == fields[i].key) {
        return fields[i].value;
      }
    }

    return {};
  }

  static Result<Header, RequestError> Parse(std::string_view view) {
    Header header;

    RequestError req_error = ParseRequest(view, &header.request);
    if (req_error != RequestError::Success) return req_error;

    header.ParseFields(view);

    return header;
  }

 private:
  void ParseFields(std::string_view view) {
    field_count = 0;

    // Skip request line
    view = view.substr(request.line_size);

    while (true) {
      size_t line_end = view.find_first_of("\r\n");

      if (line_end == 0 || line_end == std::string_view::npos) break;

      std::string_view line(view.begin(), view.begin() + line_end);

      size_t sep_pos = line.find_first_of(':');
      // Bad field that doesn't have a proper key-value separator.
      if (sep_pos == 0 || sep_pos == std::string_view::npos) continue;

      std::string_view key(line.begin(), line.begin() + sep_pos);
      std::string_view value(line.begin() + sep_pos + 1, line.end());

      fields[field_count].key = trim(key);
      fields[field_count].value = trim(value);
      ++field_count;

      view = view.substr(line_end + 2);

      if (field_count >= kMaxHeaderFields) break;
    }
  }

  static RequestError ParseRequest(std::string_view header_view, Request* request) {
    if (!request) return RequestError::Memory;

    // Parse request and fields
    size_t request_end = header_view.find_first_of("\r\n");
    if (request_end == std::string::npos) return RequestError::InvalidLine;

    request->line_size = request_end + 2;

    std::string_view request_view(header_view.begin(), header_view.begin() + request_end);

    size_t method_end = request_view.find_first_of(' ');
    if (method_end == std::string_view::npos) return RequestError::BadMethod;

    request->method = std::string_view(request_view.begin(), request_view.begin() + method_end);

    size_t uri_end = request_view.find_first_of(' ', method_end + 1);
    if (uri_end == std::string_view::npos) return RequestError::BadURI;

    request->uri = std::string_view(request_view.begin() + method_end + 1, request_view.begin() + uri_end);
    request->version = std::string_view(request_view.begin() + uri_end + 1, request_view.end());

    if (!request->version.starts_with("HTTP/")) return RequestError::BadVersion;

    return RequestError::Success;
  }
};

}  // namespace http
}  // namespace quack
