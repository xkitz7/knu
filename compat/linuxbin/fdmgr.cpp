class LinuxFdManager {
    static std::map<int, int> linux_to_native_fds;
    static int next_linux_fd;
    
public:
    static int NativeToLinux(int native_fd) {
        int linux_fd = next_linux_fd++;
        linux_to_native_fds[linux_fd] = native_fd;
        return linux_fd;
    }
    
    static int LinuxToNative(int linux_fd) {
        return linux_to_native_fds[linux_fd];
    }
};
