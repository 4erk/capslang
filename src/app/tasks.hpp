#pragma once
#include "../platform/windows_support.hpp"
#include <taskschd.h>

namespace capslang::app {
enum class TaskRole { Engine, Broker };
const wchar_t *TaskArgument(TaskRole role);
std::wstring TaskName(TaskRole role, const std::wstring &sid);
std::wstring TaskSecurity(const std::wstring &sid);
// Build and validate native definitions without registering/running anything.
// Only fixed binary and role arguments are allowed; no task parameters/macros.
HRESULT BuildTaskDefinition(ITaskService *service, const std::wstring &executable,
                            const std::wstring &sid, TaskRole role, ITaskDefinition **definition);
bool MatchesTaskDefinition(ITaskDefinition *definition, const std::wstring &executable,
                           const std::wstring &sid, TaskRole role);
bool SafeTaskSecurity(const std::wstring &sddl, const std::wstring &sid);
class Tasks {
  public:
    Tasks();
    ~Tasks();
    Tasks(const Tasks &) = delete;
    Tasks &operator=(const Tasks &) = delete;
    HRESULT Open();
    // These methods never adopt foreign tasks. SDDL is checked even when the
    // current command matches, so an editable high task cannot be trusted.
    HRESULT Read(TaskRole role, const std::wstring &executable, const std::wstring &sid,
                 bool &exists, std::wstring &xml, std::wstring &security);
    HRESULT Register(TaskRole role, const std::wstring &executable, const std::wstring &sid);
    HRESULT Start(TaskRole role, const std::wstring &executable, const std::wstring &sid,
                  DWORD session);
    HRESULT Remove(TaskRole role, const std::wstring &executable, const std::wstring &sid);
    HRESULT Restore(TaskRole role, const std::wstring &executable, const std::wstring &sid,
                    const std::wstring &xml, const std::wstring &security);

  private:
    ITaskService *service_ = nullptr;
    ITaskFolder *root_ = nullptr;
};
} // namespace capslang::app
