#pragma once

#include <optional>
#include <string_view>

namespace quack {

template <typename T, typename E>
struct Result {
  std::optional<T> data;
  E error_value = {};

  Result(E error) : error_value(error) {}
  Result(T data) : data(data) {}

  inline operator bool() const { return data.has_value(); }

  inline T& operator*() { return *data; }
  inline const T& operator*() const { return *data; }

  inline E error() const { return error_value; }
};

inline std::string_view trim_front(std::string_view view) {
  while (!view.empty() && view.front() == ' ') {
    view = view.substr(1);
  }

  return view;
}

inline std::string_view trim_back(std::string_view view) {
  while (!view.empty() && view.back() == ' ') {
    view = view.substr(0, view.size() - 1);
  }

  return view;
}

inline std::string_view trim(std::string_view view) {
  view = trim_front(view);
  view = trim_back(view);

  return view;
}

}  // namespace quack
