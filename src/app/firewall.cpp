#include "firewall.hpp"
namespace capslang::app {
namespace {
template <class T> struct Com {
    T *value = nullptr;
    ~Com() {
        if (value)
            value->Release();
    }
    T **Out() { return &value; }
    T *operator->() const { return value; }
};
struct Bstr {
    BSTR value = nullptr;
    explicit Bstr(const std::wstring &s)
        : value(SysAllocStringLen(s.data(), static_cast<UINT>(s.size()))) {}
    ~Bstr() { SysFreeString(value); }
    operator BSTR() const { return value; }
};
std::wstring Name(const std::wstring &sid) { return L"CapsLang LAN " + sid; }
bool Property(INetFwRule *rule, HRESULT (STDMETHODCALLTYPE INetFwRule::*get)(BSTR *),
              const std::wstring &expected) {
    BSTR s = nullptr;
    const bool ok = SUCCEEDED((rule->*get)(&s)) && s && _wcsicmp(s, expected.c_str()) == 0;
    SysFreeString(s);
    return ok;
}
HRESULT Rules(Com<INetFwPolicy2> &policy, Com<INetFwRules> &rules) {
    HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER,
                                  __uuidof(INetFwPolicy2), reinterpret_cast<void **>(policy.Out()));
    return FAILED(hr) ? hr : policy->get_Rules(rules.Out());
}
bool Elevated() {
    const auto e = ProcessElevation(GetCurrentProcessId());
    return e.known && e.elevated;
}
} // namespace
HRESULT BuildFirewallRule(const std::wstring &executable, const std::wstring &sid,
                          INetFwRule **output) {
    if (!output)
        return E_POINTER;
    *output = nullptr;
    DWORD error = 0;
    if (executable != InstalledExecutable(error) || sid.empty())
        return E_INVALIDARG;
    Com<INetFwRule> rule;
    HRESULT hr = CoCreateInstance(__uuidof(NetFwRule), nullptr, CLSCTX_INPROC_SERVER,
                                  __uuidof(INetFwRule), reinterpret_cast<void **>(rule.Out()));
    if (FAILED(hr))
        return hr;
    if (FAILED(hr = rule->put_Name(Bstr(Name(sid)))) ||
        FAILED(hr = rule->put_Grouping(Bstr(L"CapsLang native user installer v1"))) ||
        FAILED(hr = rule->put_Description(
                   Bstr(L"CapsLang mutually pinned TLS; local physical LAN only."))) ||
        FAILED(hr = rule->put_ApplicationName(Bstr(executable))) ||
        FAILED(hr = rule->put_Protocol(NET_FW_IP_PROTOCOL_TCP)) ||
        FAILED(hr = rule->put_LocalPorts(Bstr(std::to_wstring(kListenPort)))) ||
        FAILED(hr = rule->put_RemoteAddresses(Bstr(L"LocalSubnet"))) ||
        FAILED(hr = rule->put_Direction(NET_FW_RULE_DIR_IN)) ||
        FAILED(hr = rule->put_Profiles(NET_FW_PROFILE2_ALL)) ||
        FAILED(hr = rule->put_InterfaceTypes(Bstr(L"All"))) ||
        FAILED(hr = rule->put_Action(NET_FW_ACTION_ALLOW)) ||
        FAILED(hr = rule->put_EdgeTraversal(VARIANT_FALSE)) ||
        FAILED(hr = rule->put_Enabled(VARIANT_TRUE)))
        return hr;
    *output = rule.value;
    rule.value = nullptr;
    return S_OK;
}
bool MatchesFirewallRule(INetFwRule *r, const std::wstring &executable, const std::wstring &sid) {
    if (!r)
        return false;
    LONG protocol = 0, profiles = 0;
    NET_FW_RULE_DIRECTION direction = NET_FW_RULE_DIR_OUT;
    NET_FW_ACTION action = NET_FW_ACTION_BLOCK;
    VARIANT_BOOL edge = VARIANT_TRUE, enabled = VARIANT_FALSE;
    return Property(r, &INetFwRule::get_Name, Name(sid)) &&
           Property(r, &INetFwRule::get_Grouping, L"CapsLang native user installer v1") &&
           Property(r, &INetFwRule::get_ApplicationName, executable) &&
           Property(r, &INetFwRule::get_LocalPorts, std::to_wstring(kListenPort)) &&
           Property(r, &INetFwRule::get_RemoteAddresses, L"LocalSubnet") &&
           Property(r, &INetFwRule::get_InterfaceTypes, L"All") &&
           SUCCEEDED(r->get_Protocol(&protocol)) && protocol == NET_FW_IP_PROTOCOL_TCP &&
           SUCCEEDED(r->get_Profiles(&profiles)) && profiles == NET_FW_PROFILE2_ALL &&
           SUCCEEDED(r->get_Direction(&direction)) && direction == NET_FW_RULE_DIR_IN &&
           SUCCEEDED(r->get_Action(&action)) && action == NET_FW_ACTION_ALLOW &&
           SUCCEEDED(r->get_EdgeTraversal(&edge)) && !edge && SUCCEEDED(r->get_Enabled(&enabled)) &&
           enabled;
}
HRESULT ReadFirewallRule(const std::wstring &executable, const std::wstring &sid, bool &exists) {
    exists = false;
    Com<INetFwPolicy2> policy;
    Com<INetFwRules> rules;
    HRESULT hr = Rules(policy, rules);
    if (FAILED(hr))
        return hr;
    Com<INetFwRule> rule;
    hr = rules->Item(Bstr(Name(sid)), rule.Out());
    if (hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND))
        return S_OK;
    if (FAILED(hr))
        return hr;
    if (!MatchesFirewallRule(rule.value, executable, sid))
        return HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS);
    exists = true;
    return S_OK;
}
HRESULT EnsureFirewallRule(const std::wstring &executable, const std::wstring &sid) {
    if (!Elevated())
        return E_ACCESSDENIED;
    DWORD error = 0;
    if (!ProtectedExecutable(executable, error))
        return HRESULT_FROM_WIN32(error);
    bool exists = false;
    HRESULT hr = ReadFirewallRule(executable, sid, exists);
    if (FAILED(hr) || exists)
        return hr;
    Com<INetFwPolicy2> policy;
    Com<INetFwRules> rules;
    if (FAILED(hr = Rules(policy, rules)))
        return hr;
    Com<INetFwRule> rule;
    if (FAILED(hr = BuildFirewallRule(executable, sid, rule.Out())))
        return hr;
    return rules->Add(rule.value);
}
HRESULT RemoveFirewallRule(const std::wstring &executable, const std::wstring &sid) {
    if (!Elevated())
        return E_ACCESSDENIED;
    bool exists = false;
    HRESULT hr = ReadFirewallRule(executable, sid, exists);
    if (FAILED(hr) || !exists)
        return hr;
    Com<INetFwPolicy2> policy;
    Com<INetFwRules> rules;
    if (FAILED(hr = Rules(policy, rules)))
        return hr;
    return rules->Remove(Bstr(Name(sid)));
}
} // namespace capslang::app
