#pragma once
#include "tls.hpp"

namespace capslang::net {
// Application dispatch takes place INSIDE TLS, before either enrollment or
// state frames. Client waits for the echo before sending any protocol payload.
enum class ApplicationMode : BYTE { Session = 1, Enroll = 2, ResumeEnrollment = 3 };
bool SelectApplicationMode(TlsChannel& channel, ApplicationMode mode, DWORD& error);
bool AcceptApplicationMode(TlsChannel& channel, ApplicationMode& mode, DWORD& error);
} // namespace capslang::net
