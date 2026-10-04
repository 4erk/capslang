#pragma once
#include "paths.hpp"
#include <netfw.h>
namespace capslang::app {
constexpr unsigned kListenPort = 42519;
HRESULT BuildFirewallRule(const std::wstring &executable, const std::wstring &sid,
                          INetFwRule **rule);
bool MatchesFirewallRule(INetFwRule *rule, const std::wstring &executable, const std::wstring &sid);
HRESULT ReadFirewallRule(const std::wstring &executable, const std::wstring &sid, bool &exists);
HRESULT EnsureFirewallRule(const std::wstring &executable, const std::wstring &sid);
HRESULT RemoveFirewallRule(const std::wstring &executable, const std::wstring &sid);
} // namespace capslang::app
