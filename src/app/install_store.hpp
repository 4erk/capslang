#pragma once
#include "paths.hpp"
#include <array>

namespace capslang::app::install {
using Hash = std::array<BYTE, 32>;
enum class Phase : DWORD { Prepared = 1, Applying = 2, Committed = 3, RolledBack = 4, Removed = 5 };
struct Record {
    Phase phase = Phase::Prepared;
    std::wstring sid, engineXml, engineSecurity, brokerXml, brokerSecurity;
    bool hadExecutable = false, hadRule = false;
    Hash before{}, after{};
};
bool Encode(const Record &value, std::vector<BYTE> &bytes);
bool Decode(const std::vector<BYTE> &bytes, Record &value);
bool FileHash(const std::wstring &path, Hash &hash, DWORD &error);
std::wstring Hex(const Hash &value);
// All writes require a protected parent. No caller-supplied user-profile path
// is accepted by the elevated installation coordinator.
bool CreateRoot(const std::wstring &root, DWORD &error);
bool WriteProtected(const std::wstring &path, const std::vector<BYTE> &bytes, bool replace,
                    DWORD &error);
bool ReadProtected(const std::wstring &path, std::vector<BYTE> &bytes, DWORD &error);
bool CopyProtected(const std::wstring &source, const std::wstring &destination, Hash &hash,
                   DWORD &error);
bool SaveRecord(const std::wstring &root, const Record &value, DWORD &error);
bool LoadRecord(const std::wstring &root, Record &value, DWORD &error);
} // namespace capslang::app::install
