// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
#include "precomp.h"
#include "common.h"
#include "ProcessMonitor.h"

#define LOG_PATH "/var/log"

constexpr auto c_userName = "wslg";

constexpr auto c_x11RuntimeDir = "/tmp/.X11-unix";
constexpr auto c_xdgRuntimeDir = "/tmp/runtime-dir";
constexpr auto c_stdErrLogFile = LOG_PATH "/stderr.log";

constexpr auto c_coreDir = LOG_PATH "/dumps";

constexpr auto c_westonRdprailShell = "rdprail-shell";

void LogException(const char *message, const char *exceptionDescription) noexcept
{
    fprintf(stderr, "<3>WSLGd: %s %s", message ? message : "Exception:", exceptionDescription);
    return;
}

int main(int Argc, char *Argv[])
try {
    wil::g_LogExceptionCallback = LogException;

    // Open a file for logging errors and set it to stderr for WSLGd as well as any child process.
    {
        wil::unique_fd stdErrLogFd(open(c_stdErrLogFile, (O_RDWR | O_CREAT), (S_IRUSR | S_IRGRP | S_IROTH)));
        if (stdErrLogFd && (stdErrLogFd.get() != STDERR_FILENO)) {
            dup2(stdErrLogFd.get(), STDERR_FILENO);
        }
    }

    // Restore default processing for SIGCHLD as both WSLGd and Xwayland depends on this.
    signal(SIGCHLD, SIG_DFL);

    // Ensure the daemon is launched as root.
    if (geteuid() != 0) {
        LOG_ERROR("must be run as root.");
        return 1;
    }

    std::filesystem::create_directories(LOG_PATH);
    THROW_LAST_ERROR_IF(chmod(LOG_PATH, 0777) < 0);

    // Create a process monitor to track child processes
    wslgd::ProcessMonitor monitor(c_userName);
    auto passwordEntry = monitor.GetUserInfo();

    std::filesystem::create_directories(c_x11RuntimeDir);
    THROW_LAST_ERROR_IF(chmod(c_x11RuntimeDir, 0777) < 0);

    std::filesystem::create_directories(c_xdgRuntimeDir);
    THROW_LAST_ERROR_IF(chmod(c_xdgRuntimeDir, 0700) < 0);
    THROW_LAST_ERROR_IF(chown(c_xdgRuntimeDir, passwordEntry->pw_uid, passwordEntry->pw_gid) < 0);

    // Set required environment variables.
    struct envVar{ const char* name; const char* value; };
    envVar variables[] = {
        {"HOME", passwordEntry->pw_dir},
        {"USER", passwordEntry->pw_name},
        {"LOGNAME", passwordEntry->pw_name},
        {"SHELL", passwordEntry->pw_shell},
        {"PATH", "/usr/sbin:/usr/bin:/sbin:/bin:/usr/games"},
        {"XDG_RUNTIME_DIR", c_xdgRuntimeDir},
        {"WAYLAND_DISPLAY", "wayland-0"},
        {"DISPLAY", ":0"},
        {"XCURSOR_PATH", "/usr/share/icons"},
        {"XCURSOR_THEME", "whiteglass"},
        {"XCURSOR_SIZE", "16"},
        {"WSL2_DEFAULT_APP_ICON", "/usr/share/icons/wsl/linux.png"},
        {"WSL2_DEFAULT_APP_OVERLAY_ICON", "/usr/share/icons/wsl/linux.png"},
        {"WESTON_DISABLE_ABSTRACT_FD", "1"}
    };

    for (auto &var : variables) {
        THROW_LAST_ERROR_IF(setenv(var.name, var.value, true) < 0);
    }

    // "ulimits -c unlimited" for core dumps.
    struct rlimit limit;
    limit.rlim_cur = RLIM_INFINITY;
    limit.rlim_max = RLIM_INFINITY;
    THROW_LAST_ERROR_IF(setrlimit(RLIMIT_CORE, &limit) < 0);

    // create folder to store core files.
    std::filesystem::create_directories(c_coreDir);
    THROW_LAST_ERROR_IF(chmod(c_coreDir, 0777) < 0);

    // Check if weston shell override is specified.
    // Otherwise, default shell is 'rdprail-shell'.
    bool isRdprailShell;
    std::string westonShellName;
    westonShellName = c_westonRdprailShell;

    // Construct shell option string.
    std::string westonShellOption("--shell=");
    westonShellOption += westonShellName;
    westonShellOption += ".so";

    // Construct logger option string.
    // By default, enable standard log and rdp-backend.
    std::string westonLoggerOption("--logger-scopes=log,rdp-backend");
    westonLoggerOption += ",";
    westonLoggerOption += c_westonRdprailShell;

    // Launch weston.
    // N.B. Additional capabilities are needed to setns to the mount namespace of the user distro.
    monitor.LaunchProcess(std::vector<std::string>{
        "/usr/bin/weston",
        "--backend=rdp-backend.so",
        "--xwayland",
        std::move(westonShellOption),
        std::move(westonLoggerOption),
        "--log=" LOG_PATH "/weston.log"
        },
        std::vector<cap_value_t>{CAP_SYS_ADMIN, CAP_SYS_CHROOT, CAP_SYS_PTRACE}
    );

    return monitor.Run();
}
CATCH_RETURN_ERRNO();
