class LinuxSyscallTranslator {
private:
    static std::unordered_map<int, LinuxSyscallHandler> syscall_handlers_;
    
public:
    static void Initialize() {
        RegisterHandler(LINUX_SYS_READ, &TranslateRead);
        RegisterHandler(LINUX_SYS_WRITE, &TranslateWrite);
        RegisterHandler(LINUX_SYS_OPEN, &TranslateOpen);
        RegisterHandler(LINUX_SYS_CLOSE, &TranslateClose);
        RegisterHandler(LINUX_SYS_BRK, &TranslateBrk);
        RegisterHandler(LINUX_SYS_STAT, &TranslateStat);
        RegisterHandler(LINUX_SYS_FSTAT, &TranslateFstat);
        RegisterHandler(LINUX_SYS_MMAP, &TranslateMmap);
        RegisterHandler(LINUX_SYS_FSTAT, &TranslateFstat);
        RegisterHandler(LINUX_SYS_MUNMAP, &TranslateMunmap);
        RegisterHandler(LINUX_SYS_FORK, &TranslateFork);
        RegisterHandler(LINUX_SYS_EXECVE, &TranslateExecve);
        RegisterHandler(LINUX_SYS_EXIT, &TranslateExit);
        RegisterHandler(LINUX_SYS_SIGACTION, &TranslateSigaction);
        RegisterHandler(LINUX_SYS_KILL, &TranslateKill);
        RegisterHandler(LINUX_SYS_SIGRETURN, &TranslateSigReturn);
        RegisterHandler(LINUX_SYS_SOCKET, &TranslateSocket);
        RegisterHandler(LINUX_SYS_BIND, &TranslateBind);
        RegisterHandler(LINUX_SYS_CONNECT, &TranslateConnect);
        RegisterHandler(LINUX_SYS_CLOCK_GETTIME, &TranslateClock_gettime);
        RegisterHandler(LINUX_SYS_GETTIMEOFDAY, &TranslateGettimeofday);
    }
    
    static int Dispatch(int linux_syscall, uint64_t arg1, uint64_t arg2, 
                       uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6) {
        auto handler = syscall_handlers_[linux_syscall];
        if (handler) {
            return handler(arg1, arg2, arg3, arg4, arg5, arg6);
        }
        return -LINUX_ENOSYS;
    }
};
