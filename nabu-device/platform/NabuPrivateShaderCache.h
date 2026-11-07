#pragma once
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <limits.h>
#include <mutex>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace nabu_shader_cache {

inline std::mutex &environmentMutex() {
    static std::mutex mutex;
    return mutex;
}

struct SavedVariable {
    const char *name;
    bool present;
    std::string value;

    explicit SavedVariable(const char *variable) : name(variable) {
        const char *current = getenv(name);
        present = current != nullptr;
        if (present) value = current;
    }

    void restore() const {
        if (present) setenv(name, value.c_str(), 1);
        else unsetenv(name);
    }
};

inline bool ownedDirectory(int fd) {
    struct stat attributes{};
    return fd >= 0 && fstat(fd, &attributes) == 0 && S_ISDIR(attributes.st_mode) &&
        attributes.st_uid == getuid() && (attributes.st_mode & 0700) == 0700 &&
        (attributes.st_mode & 0022) == 0;
}

inline std::string openedDirectoryPath(int fd) {
    char path[PATH_MAX];
#if defined(__APPLE__)
    if (fcntl(fd, F_GETPATH, path) != 0) return {};
#elif defined(__linux__)
    char descriptor[64];
    snprintf(descriptor, sizeof descriptor, "/proc/self/fd/%d", fd);
    const ssize_t length = readlink(descriptor, path, sizeof path - 1);
    if (length <= 0 || static_cast<size_t>(length) >= sizeof path - 1) return {};
    path[length] = '\0';
#else
    return {};
#endif
    // The path handed to Mesa must still name the descriptor we validated.
    struct stat opened{}, named{};
    if (fstat(fd, &opened) != 0 || lstat(path, &named) != 0 ||
        !S_ISDIR(named.st_mode) || opened.st_dev != named.st_dev || opened.st_ino != named.st_ino)
        return {};
    return path;
}

inline std::string writablePrivateCache(const char *root, int &cache) {
    cache = -1;
    if (!root || root[0] != '/' || root[1] == '\0') return {};
    // Existing callers select the parent directory. Create the private leaf if
    // this is the first device open, before Mesa's own cache initialization.
    if (mkdir(root, 0700) != 0 && errno != EEXIST) return {};
    const int parent = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (!ownedDirectory(parent)) {
        if (parent >= 0) close(parent);
        return {};
    }
    const bool made = mkdirat(parent, "ir3", 0700) == 0 || errno == EEXIST;
    cache = made ? openat(parent, "ir3", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC) : -1;
    close(parent);
    if (!ownedDirectory(cache)) {
        if (cache >= 0) close(cache);
        cache = -1;
        return {};
    }
    const std::string path = openedDirectoryPath(cache);
    // Environment serializes these calls. An old colliding probe is left alone.
    static unsigned sequence;
    char probe[64];
    int file = -1;
    for (unsigned attempt = 0; !path.empty() && attempt < 8; ++attempt) {
        snprintf(probe, sizeof probe, ".nabu-write-%ld-%u", (long)getpid(), sequence++);
        file = openat(cache, probe, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (file >= 0 || errno != EEXIST) break;
    }
    bool writable = false;
    if (file >= 0) {
        writable = write(file, "x", 1) == 1;
        const int closed = close(file);
        const int removed = unlinkat(cache, probe, 0);
        writable = writable && closed == 0 && removed == 0;
    }
    if (!writable) {
        close(cache);
        cache = -1;
        return {};
    }
    return path;
}

// Mesa keeps the path in its cache instance. Restore initialization variables
// after device creation so a root retry or a later open inherits its caller.
class Environment {
    std::unique_lock<std::mutex> lock_;
    SavedVariable directory_;
    SavedVariable disabled_;
    int cache_ = -1;
    bool configured_ = false;

public:
    explicit Environment(const char *root) : lock_(environmentMutex()),
        directory_("MESA_SHADER_CACHE_DIR"), disabled_("MESA_SHADER_CACHE_DISABLE") {
        const std::string path = writablePrivateCache(root, cache_);
        configured_ = !path.empty() && setenv(directory_.name, path.c_str(), 1) == 0;
        if (!configured_) {
            // Do not reuse an unrelated old path after an unsuccessful setenv.
            unsetenv(directory_.name);
            setenv(disabled_.name, "true", 1);
        }
        // A caller's explicit disable is preserved on the configured path.
    }

    ~Environment() { finish(); }

    void finish() {
        if (!lock_.owns_lock()) return;
        directory_.restore();
        disabled_.restore();
        if (cache_ >= 0) {
            close(cache_);
            cache_ = -1;
        }
        lock_.unlock();
    }

    bool pathConfigured() const { return configured_; }
    Environment(const Environment &) = delete;
    Environment &operator=(const Environment &) = delete;
};

} // namespace nabu_shader_cache
