#pragma once
#include "broker.hpp"
namespace capslang::app {
int RunWindow(Broker &broker, const std::wstring &directory, bool show,
              HANDLE ownedEngineShutdown = nullptr, bool maintainSaver = false);
} // namespace capslang::app
