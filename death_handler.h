/*

  Copyright (c) 2012, Samsung R&D Institute Russia
  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

  1. Redistributions of source code must retain the above copyright notice, this
     list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright notice,
     this list of conditions and the following disclaimer in the documentation
     and/or other materials provided with the distribution.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
  ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

 */

/*! @file death_handler.h
 *  @brief Declaration of the SIGSEGV/SIGABRT handler which prints the debug stack
 *  trace.
 *  @author Markovtsev Vadim <gmarkhor@gmail.com>
 *  @version 1.0
 *  @license Simplified BSD License
 *  @copyright 2012 Samsung R&D Institute Russia, 2016 Moscow Institute of Physics and Technology
 */

/*! @mainpage SIGSEGV/SIGABRT handler which prints the debug stack trace.
 *  Example
 *  =======
 *  ~~~~{.cc}
 *  #include "death_handler.h"
 *
 *  int main() {
 *    DeathHandler dh;
 *    int* p = NULL;
 *    *p = 0;
 *    return 0;
 *  }
 *  ~~~~
 *
 *  Underlying code style is very similar to [Google C++ Style Guide](http://google-styleguide.googlecode.com/svn/trunk/cppguide.xml). It is checked with cpplint.py.
 */

#ifndef WIN32

#ifndef DEATH_HANDLER_H_
#define DEATH_HANDLER_H_

#include <stddef.h>
#include <unistd.h>
#include <assert.h>
#include <execinfo.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dlfcn.h>
#ifdef __APPLE__
#include <malloc/malloc.h>
#include <sys/mman.h>
#endif

// We have to override malloc() and free()
extern "C" {
    void* __malloc_impl(size_t size);
#ifdef __linux__
    void* malloc(size_t size) throw ();
    void free(void* ptr) throw ();
#elif defined(__APPLE__)
    void* __malloc_zone(struct _malloc_zone_t* zone, size_t size);
    void __free_zone(struct _malloc_zone_t* zone, void* ptr);
#endif
}

#ifdef __linux__
// Comment this out on systems without quick_exit()
#define QUICK_EXIT
#endif

/// @brief This class installs a SEGFAULT signal handler to print
/// a nice stack trace and (if requested) generate a core dump.
/// @details In DeathHandler's constructor, a SEGFAULT signal handler
/// is installed via sigaction(). If your program encounters a segmentation
/// fault, the call stack is unwinded with backtrace(), converted into
/// function names with line numbers via addr2line (fork() + execlp()).
/// Addresses from shared libraries are also converted thanks to dladdr().
/// All C++ symbols are demangled. Printed stack trace includes the faulty
/// thread id obtained with pthread_self() and each line contains the process
/// id to distinguish several stack traces printed by different processes at
/// the same time.

class DeathHandler {
public:
    typedef ssize_t(*OutputCallback)(const char*, size_t);

    /// @brief Installs the SIGSEGV/etc. signal handler.
    /// @param altstack If true, allocate and use a dedicated signal handler stack.
    /// backtrace() will report nothing then, but the handler will survive a stack
    /// overflow.
    DeathHandler(bool altstack = false);
    /// @brief This is called on normal program termination. Previously installed
    /// SIGSEGV and SIGABRT signal handlers are removed.
    ~DeathHandler();

    /// @brief Sets the value of cleanup property.
    /// @details If cleanup is set to true, program attempts to run all static
    /// destructors and atexit() callbacks before terminating. If
    /// generate_core_dump is set to true, this property is ignored.
    /// @note Default value of this property is true.
    bool cleanup() const;

    /// @brief Returns the value of cleanup property.
    /// @details If cleanup is set to true, program attempts to run all static
    /// destructors and atexit() callbacks before terminating. If
    /// generate_core_dump is set to true, this property is ignored.
    /// @note Default value of this property is true.
    void set_cleanup(bool value);

    /// @brief Returns the current value of generate_core_dump property.
    /// @details If generate_core_dump is set to true, a core dump will
    /// be generated when the program terminates. This behavior
    /// is implemented using abort(). cleanup property is ignored.
    /// @note You need to set ulimit to a value different from the default 0
    /// (for example, "ulimit -c unlimited") to enable core dumps generation
    /// on your system.
    /// @note Default value of this property is true.
    bool generate_core_dump() const;

    /// @brief Sets the value of generate_core_dump property.
    /// @details If generate_core_dump is set to true, a core dump will
    /// be generated when the program terminates. This behavior
    /// is implemented using abort(). cleanup property is ignored.
    /// @note You need to set ulimit to a value different from the default 0
    /// (for example, "ulimit -c unlimited") to enable core dumps generation
    /// on your system.
    /// @note Default value of this property is true.
    void set_generate_core_dump(bool value);

#ifdef QUICK_EXIT
    /// @brief Returns the value of quick_exit property.
    /// @details If quick_exit is set to true, program will be terminated with
    /// quick_exit() call. generate_core_dump and cleanup properties are
    /// ignored.
    /// @note Default value is false.
    bool quick_exit() const;

    /// @brief Sets the value of quick_exit property.
    /// @details If quick_exit is set to true, program will be terminated with
    /// quick_exit() call. generate_core_dump and cleanup properties are
    /// ignored.
    /// @note Default value is false.
    void set_quick_exit(bool value);
#endif

    /// @brief Returns the depth of the stack trace.
    /// @note Default value is 16.
    int frames_count() const;

    /// @brief Sets the depth of the stack trace. Accepted range is 1..100.
    /// @note Default value is 16.
    void set_frames_count(int value);

    /// @brief Returns the value indicating whether to shorten stack trace paths
    /// by cutting off the common root between each path and the current working
    /// directory.
    /// @note Default value is true.
    bool cut_common_path_root() const;

    /// @brief Sets the value indicating whether to shorten stack trace paths
    /// by cutting off the common root between each path and the current working
    /// directory.
    /// @note Default value is true.
    void set_cut_common_path_root(bool value);

    /// @brief Returns the value indicating whether to shorten stack trace paths
    /// by cutting off the relative part (e.g., "../../..").
    /// @note Default value is true.
    bool cut_relative_paths() const;

    /// @brief Sets the value indicating whether to shorten stack trace paths
    /// by cutting off the relative part (e.g., "../../..").
    /// @note Default value is true.
    void set_cut_relative_paths(bool value);

    /// @brief Returns the value indicating whether to append the process id
    /// to each stack trace line.
    /// @note Default value is false.
    bool append_pid() const;

    /// @brief Sets the value indicating whether to append the process id
    /// to each stack trace line.
    /// @note Default value is false.
    void set_append_pid(bool value);

    /// @brief Returns the value indicating whether to color the output
    /// with ANSI escape sequences.
    /// @note Default value is true.
    bool color_output() const;

    /// @brief Sets the value indicating whether to color the output
    /// with ANSI escape sequences.
    /// @note Default value is true.
    void set_color_output(bool value);

    /// @brief Returns the value indicating whether to do a thread-safe
    /// stack trace printing, stopping all running threads by forking.
    /// @note Default value is true.
    bool thread_safe() const;

    /// @brief Sets the value indicating whether to do a thread-safe stack trace
    /// printing, stopping all running threads by forking.
    /// @note Default value is true.
    void set_thread_safe(bool value);

    /// @brief Returns the current output callback.
    /// @note Default value is write to stderr.
    OutputCallback output_callback() const;

    /// @brief Changes output callback (that is, how to write the trace, etc.).
    /// @note Default value is write to stderr.
    void set_output_callback(OutputCallback value);

private:
    friend void* ::__malloc_impl(size_t);
#ifdef __linux__
    friend void* ::malloc(size_t) throw ();
    friend void ::free(void*) throw ();
#elif defined(__APPLE__)
    friend void* ::__malloc_zone(struct _malloc_zone_t*, size_t);
    friend void ::__free_zone(struct _malloc_zone_t*, void*);
#endif
    /// @brief Reentrant printing to stderr.
    inline static void print(const char* msg, size_t len = 0);

    /// @brief The size of the preallocated memory to use in the signal handler.
    static const size_t kNeededMemory;

    static void HandleSignal(int sig, void* info, void* secret);

    /// @brief Used to workaround backtrace() usage of malloc().
    static void* malloc_;
    static void* free_;
    static bool heap_trap_active_;

    static bool generate_core_dump_;
    static bool cleanup_;
#ifdef QUICK_EXIT
    static bool quick_exit_;
#endif
    static int frames_count_;
    static bool cut_common_path_root_;
    static bool cut_relative_paths_;
    static bool append_pid_;
    static bool color_output_;
    static bool thread_safe_;
    static OutputCallback output_callback_;
    /// @brief The preallocated memory to use in the signal handler.
    static char* memory_;
};



// Impl

#define INLINE __attribute__((always_inline)) inline

namespace Safe {
    INLINE void print(const char *msg, size_t len = 0);
} // namespace Safe


extern "C" {

    void* __malloc_impl(size_t size) {
        char* malloc_buffer =
                DeathHandler::memory_ + DeathHandler::kNeededMemory - 512;
        if (size > 512U) {
            const char* msg = "malloc() replacement function should not return "
                    "a memory block larger than 512 bytes\n";
            DeathHandler::print(msg, strlen(msg) + 1);
            _Exit(EXIT_FAILURE);
        }
        return malloc_buffer;
    }

#ifdef __linux__

    void* malloc(size_t size) throw () {
        if (!DeathHandler::heap_trap_active_) {
            if (!DeathHandler::malloc_) {
                DeathHandler::malloc_ = dlsym(RTLD_NEXT, "malloc");
            }
            return ((void*(*)(size_t))DeathHandler::malloc_)(size);
        }
        return __malloc_impl(size);
    }

    void free(void* ptr) throw () {
        if (!DeathHandler::heap_trap_active_) {
            if (!DeathHandler::free_) {
                DeathHandler::free_ = dlsym(RTLD_NEXT, "free");
            }
            ((void(*)(void*))DeathHandler::free_)(ptr);
        }
        // no-op
    }
#elif defined(__APPLE__)

    void* __malloc_zone(struct _malloc_zone_t* zone, size_t size) {
        if (!DeathHandler::heap_trap_active_) {
            return ((void*(*)(struct _malloc_zone_t*, size_t))
            DeathHandler::malloc_)(zone, size);
        }
        return __malloc_impl(size);
    }

    void __free_zone(struct _malloc_zone_t* zone, void *ptr) {
        if (!DeathHandler::heap_trap_active_) {
            return ((void(*)(struct _malloc_zone_t*, void*))
            DeathHandler::free_)(zone, ptr);
        }
        // no-op
    }
#endif // #ifdef __linux__
} // extern "C"

#ifdef __APPLE__

static void SetMallocZone(malloc_zone_t* zone, void* malloc, void* free,
        void** zone_malloc = NULL, void** zone_free = NULL) {
    if (zone_malloc) {
        *zone_malloc = reinterpret_cast<void*> (zone->malloc);
    }
    if (zone_free) {
        *zone_free = reinterpret_cast<void*> (zone->free);
    }
    mprotect(zone, sizeof (*zone), PROT_READ | PROT_WRITE);
    zone->malloc = (void*(*)(struct _malloc_zone_t*, size_t))malloc;
    zone->free = (void(*)(struct _malloc_zone_t*, void*))free;
    mprotect(zone, sizeof (*zone), PROT_READ);
}
#endif

#pragma GCC poison malloc realloc free backtrace_symbols \
  printf fprintf sprintf snprintf scanf sscanf  // NOLINT(runtime/printf)

#define checked(x) do { if ((x) <= 0) _Exit(EXIT_FAILURE); } while (false)

/// @brief This namespace contains some basic supplements
/// of the needed libc functions which potentially use heap.
namespace Safe {
    /// @brief Converts an integer to a preallocated string.
    /// @pre base must be less than or equal to 16.

    INLINE char *itoa(int val, char* memory, int base = 10) {
        char* res = memory;
        if (val == 0) {
            res[0] = '0';
            res[1] = '\0';
            return res;
        }
        const int res_max_length = 32;
        int i;
        bool negative = val < 0;
        res[res_max_length - 1] = 0;
        for (i = res_max_length - 2; val != 0 && i != 0; i--, val /= base) {
            res[i] = "0123456789ABCDEF"[val % base];
        }
        if (negative) {
            res[i--] = '-';
        }
        return &res[i + 1];
    }

    /// @brief Converts an unsigned integer to a preallocated string.
    /// @pre base must be less than or equal to 16.

    INLINE char *utoa(uint64_t val, char* memory, int base = 10) {
        char* res = memory;
        if (val == 0) {
            res[0] = '0';
            res[1] = '\0';
            return res;
        }
        const int res_max_length = 32;
        int i;
        res[res_max_length - 1] = 0;
        for (i = res_max_length - 2; val != 0 && i != 0; i--, val /= base) {
            res[i] = "0123456789abcdef"[val % base];
        }
        return &res[i + 1];
    }

    /// @brief Converts a pointer to a preallocated string.

    INLINE char *ptoa(const void *val, char* memory) {
        char* buf = utoa(reinterpret_cast<uint64_t> (val), memory + 32, 16);
        char* result = memory; // 32
        strcpy(result + 2, buf); // NOLINT(runtime/printf
        result[0] = '0';
        result[1] = 'x';
        return result;
    }

    ssize_t write2stderr(const char* msg, size_t len) {
        return write(STDERR_FILENO, msg, len);
    }
} // namespace Safe

const size_t DeathHandler::kNeededMemory = 16384;
bool DeathHandler::generate_core_dump_ = true;
bool DeathHandler::cleanup_ = true;
#ifdef QUICK_EXIT
bool DeathHandler::quick_exit_ = false;
#endif
int DeathHandler::frames_count_ = 16;
bool DeathHandler::cut_common_path_root_ = true;
bool DeathHandler::cut_relative_paths_ = true;
bool DeathHandler::append_pid_ = false;
bool DeathHandler::color_output_ = true;
bool DeathHandler::thread_safe_ = true;
char* DeathHandler::memory_ = NULL;
void* DeathHandler::malloc_ = NULL;
void* DeathHandler::free_ = NULL;
bool DeathHandler::heap_trap_active_ = false;
DeathHandler::OutputCallback DeathHandler::output_callback_ = Safe::write2stderr;

typedef void (*sa_sigaction_handler) (int, siginfo_t *, void *);

DeathHandler::DeathHandler(bool altstack) {
    if (memory_ == NULL) {
        memory_ = new char[kNeededMemory + (altstack ? MINSIGSTKSZ : 0)];
    }
    if (altstack) {
        stack_t altstack;
        altstack.ss_sp = memory_ + kNeededMemory;
        altstack.ss_size = MINSIGSTKSZ;
        altstack.ss_flags = 0;
        if (sigaltstack(&altstack, NULL) < 0) {
            perror("DeathHandler - sigaltstack()");
        }
    }
    struct sigaction sa;
    sa.sa_sigaction = (sa_sigaction_handler) HandleSignal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_SIGINFO | (altstack ? SA_ONSTACK : 0);
    if (sigaction(SIGSEGV, &sa, NULL) < 0) {
        perror("DeathHandler - sigaction(SIGSEGV)");
    }
    if (sigaction(SIGABRT, &sa, NULL) < 0) {
        perror("DeathHandler - sigaction(SIGABBRT)");
    }
    if (sigaction(SIGFPE, &sa, NULL) < 0) {
        perror("DeathHandler - sigaction(SIGFPE)");
    }
#ifdef __APPLE__
    malloc_zone_t* zone = malloc_default_zone();
    if (!zone) {
        print("Failed to override malloc() and free()");
        return;
    }
    // Override malloc() and free()
    SetMallocZone(zone, reinterpret_cast<void*> (__malloc_zone),
            reinterpret_cast<void*> (__free_zone), &malloc_, &free_);
#endif
}

DeathHandler::~DeathHandler() {
    // Disable alternative signal handler stack
    stack_t altstack;
    altstack.ss_sp = NULL;
    altstack.ss_size = 0;
    altstack.ss_flags = SS_DISABLE;
    sigaltstack(&altstack, NULL);

    struct sigaction sa;

    sigaction(SIGSEGV, NULL, &sa);
    sa.sa_handler = SIG_DFL;
    sigaction(SIGSEGV, &sa, NULL);

    sigaction(SIGABRT, NULL, &sa);
    sa.sa_handler = SIG_DFL;
    sigaction(SIGABRT, &sa, NULL);

    sigaction(SIGFPE, NULL, &sa);
    sa.sa_handler = SIG_DFL;
    sigaction(SIGFPE, &sa, NULL);
    delete[] memory_;

#ifdef __APPLE__
    malloc_zone_t* zone = malloc_default_zone();
    SetMallocZone(zone, malloc_, free_);
#endif
}

void DeathHandler::print(const char* msg, size_t len) {
    if (len > 0) {
        checked(output_callback_(msg, len));
    } else {
        checked(output_callback_(msg, strlen(msg)));
    }
}

bool DeathHandler::generate_core_dump() const {
    return generate_core_dump_;
}

void DeathHandler::set_generate_core_dump(bool value) {
    generate_core_dump_ = value;
}

bool DeathHandler::cleanup() const {
    return cleanup_;
}

void DeathHandler::set_cleanup(bool value) {
    cleanup_ = value;
}

#ifdef QUICK_EXIT

bool DeathHandler::quick_exit() const {
    return quick_exit_;
}

void DeathHandler::set_quick_exit(bool value) {
    quick_exit_ = value;
}
#endif

int DeathHandler::frames_count() const {
    return frames_count_;
}

void DeathHandler::set_frames_count(int value) {
    assert(value > 0 && value <= 100);
    frames_count_ = value;
}

bool DeathHandler::cut_common_path_root() const {
    return cut_common_path_root_;
}

void DeathHandler::set_cut_common_path_root(bool value) {
    cut_common_path_root_ = value;
}

bool DeathHandler::cut_relative_paths() const {
    return cut_relative_paths_;
}

void DeathHandler::set_cut_relative_paths(bool value) {
    cut_relative_paths_ = value;
}

bool DeathHandler::append_pid() const {
    return append_pid_;
}

void DeathHandler::set_append_pid(bool value) {
    append_pid_ = value;
}

bool DeathHandler::color_output() const {
    return color_output_;
}

void DeathHandler::set_color_output(bool value) {
    color_output_ = value;
}

bool DeathHandler::thread_safe() const {
    return thread_safe_;
}

void DeathHandler::set_thread_safe(bool value) {
    thread_safe_ = value;
}

DeathHandler::OutputCallback DeathHandler::output_callback() const {
    return output_callback_;
}

void DeathHandler::set_output_callback(DeathHandler::OutputCallback value) {
    output_callback_ = value;
}

INLINE static void safe_abort() {
    struct sigaction sa;
    sigaction(SIGABRT, NULL, &sa);
    sa.sa_handler = SIG_DFL;
    kill(getppid(), SIGCONT);
    sigaction(SIGABRT, &sa, NULL);
    abort();
}

/// @brief Invokes addr2line utility to determine the function name
/// and the line information from an address in the code segment.

static char *addr2line(const char *image, void *addr, bool color_output,
        char** memory) {
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        safe_abort();
    }
    pid_t pid = fork();
    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        if (execlp("addr2line", "addr2line",
                Safe::ptoa(addr, *memory), "-f", "-C", "-e", image,
                reinterpret_cast<void*> (NULL)) == -1) {
            safe_abort();
        }
    }

    close(pipefd[1]);
    const int line_max_length = 4096;
    char* line = *memory;
    *memory += line_max_length;
    ssize_t len = read(pipefd[0], line, line_max_length);
    close(pipefd[0]);
    if (len == 0) {
        safe_abort();
    }
    line[len] = 0;

    if (waitpid(pid, NULL, 0) != pid) {
        safe_abort();
    }
    if (line[0] == '?') {
        char* straddr = Safe::ptoa(addr, *memory);
        if (color_output) {
            strcpy(line, "\033[32;1m"); // NOLINT(runtime/printf)
        }
        strcat(line, straddr); // NOLINT(runtime/printf)
        if (color_output) {
            strcat(line, "\033[0m"); // NOLINT(runtime/printf)
        }
        strcat(line, " at "); // NOLINT(runtime/printf)
        strcat(line, image); // NOLINT(runtime/printf)
        strcat(line, " "); // NOLINT(runtime/printf)
    } else {
        if (*(strstr(line, "\n") + 1) == '?') {
            char* straddr = Safe::ptoa(addr, *memory);
            strcpy(strstr(line, "\n") + 1, image); // NOLINT(runtime/printf)
            strcat(line, ":"); // NOLINT(runtime/printf)
            strcat(line, straddr); // NOLINT(runtime/printf)
            strcat(line, "\n"); // NOLINT(runtime/printf)
        }
    }
    return line;
}

#if (__GNUC__ > 4) || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif

void DeathHandler::HandleSignal(int sig, void * /* info */, void *secret) {
    // Stop all other running threads by forking
    pid_t forkedPid = fork();
    if (forkedPid != 0) {
        int status;
        if (thread_safe_) {
            // Freeze the original process, until it's child prints the stack trace
            kill(getpid(), SIGSTOP);
            // Wait for the child without blocking and exit as soon as possible,
            // so that no zombies are left.
            waitpid(forkedPid, &status, WNOHANG);
        } else {
            // Wait for the child, blocking only the current thread.
            // All other threads will continue to run, potentially crashing the parent.
            waitpid(forkedPid, &status, 0);
        }
#ifdef QUICK_EXIT
        if (quick_exit_) {
            ::quick_exit(EXIT_FAILURE);
        }
#endif
        if (generate_core_dump_) {
            struct sigaction sa;
            sigaction(SIGABRT, NULL, &sa);
            sa.sa_handler = SIG_DFL;
            sigaction(SIGABRT, &sa, NULL);
            abort();
        } else {
            if (cleanup_) {
                exit(EXIT_FAILURE);
            } else {
                _Exit(EXIT_FAILURE);
            }
        }
    }

    ucontext_t *uc = reinterpret_cast<ucontext_t *> (secret);

    if (dup2(STDERR_FILENO, STDOUT_FILENO) == -1) { // redirect stdout to stderr
        print("Failed to redirect stdout to stderr\n");
    }
    char* memory = memory_;
    {
        char* msg = memory;
        const int msg_max_length = 128;
        if (color_output_) {
            // \033[31;1mSegmentation fault\033[0m \033[33;1m(%i)\033[0m\n
            strcpy(msg, "\033[31;1m"); // NOLINT(runtime/printf)
        } else {
            msg[0] = '\0';
        }
        switch (sig) {
            case SIGSEGV:
                strcat(msg, "Segmentation fault"); // NOLINT(runtime/printf)
                break;
            case SIGABRT:
                strcat(msg, "Aborted"); // NOLINT(runtime/printf)
                break;
            case SIGFPE:
                strcat(msg, "Floating point exception"); // NOLINT(runtime/printf)
                break;
            default:
                strcat(msg, "Caught signal "); // NOLINT(runtime/printf)
                strcat(msg, Safe::itoa(sig, msg + msg_max_length)); // NOLINT(*)
                break;
        }
        if (color_output_) {
            strcat(msg, "\033[0m"); // NOLINT(runtime/printf)
        }
        strcat(msg, " (thread "); // NOLINT(runtime/printf)
        if (color_output_) {
            strcat(msg, "\033[33;1m"); // NOLINT(runtime/printf)
        }
#ifndef __APPLE__
        strcat(msg, Safe::utoa(pthread_self(), msg + msg_max_length)); // NOLINT(*)
#else
        strcat(msg, Safe::ptoa(pthread_self(), msg + msg_max_length)); // NOLINT(*)
#endif
        if (color_output_) {
            strcat(msg, "\033[0m"); // NOLINT(runtime/printf)
        }
        strcat(msg, ", pid "); // NOLINT(runtime/printf)
        if (color_output_) {
            strcat(msg, "\033[33;1m"); // NOLINT(runtime/printf)
        }
        strcat(msg, Safe::itoa(getppid(), msg + msg_max_length)); // NOLINT(*)
        if (color_output_) {
            strcat(msg, "\033[0m"); // NOLINT(runtime/printf)
        }
        strcat(msg, ")"); // NOLINT(runtime/printf)
        print(msg);
    }

    print("\nStack trace:\n");
    void **trace = reinterpret_cast<void**> (memory);
    memory += (frames_count_ + 2) * sizeof (void*);
    // Workaround malloc() inside backtrace()
    heap_trap_active_ = true;
    int trace_size = backtrace(trace, frames_count_ + 2);
    heap_trap_active_ = false;
    if (trace_size <= 2) {
        safe_abort();
    }

    // Overwrite sigaction with caller's address
#ifdef __linux__
#if defined(__arm__)
    trace[1] = reinterpret_cast<void *> (uc->uc_mcontext.arm_pc);
#elif defined(__aarch64__)
    trace[1] = reinterpret_cast<void *> (uc->uc_mcontext.pc);
#else
#if !defined(__i386__) && !defined(__x86_64__)
#error Only ARM, aarch64, x86 and x86-64 are supported
#endif
#if defined(__x86_64__)
    trace[1] = reinterpret_cast<void *> (uc->uc_mcontext.gregs[REG_RIP]);
#else
    trace[1] = reinterpret_cast<void *> (uc->uc_mcontext.gregs[REG_EIP]);
#endif
#endif

    const int path_max_length = 2048;
    char* name_buf = memory;
    ssize_t name_buf_length = readlink("/proc/self/exe", name_buf,
            path_max_length - 1);
    if (name_buf_length < 1) {
        safe_abort();
    }
    name_buf[name_buf_length] = 0;
    memory += name_buf_length + 1;
    char* cwd = memory;
    if (getcwd(cwd, path_max_length) == NULL) {
        safe_abort();
    }
    strcat(cwd, "/"); // NOLINT(runtime/printf)
    memory += strlen(cwd) + 1;
    char* prev_memory = memory;

    int stackOffset = trace[2] == trace[1] ? 2 : 1;
    for (int i = stackOffset; i < trace_size; i++) {
        memory = prev_memory;
        char *line;
        Dl_info dlinf;
        if (dladdr(trace[i], &dlinf) == 0 || dlinf.dli_fname[0] != '/' ||
                !strcmp(name_buf, dlinf.dli_fname)) {
            line = addr2line(name_buf, trace[i], color_output_, &memory);
        } else {
            line = addr2line(dlinf.dli_fname, reinterpret_cast<void *> (
                    reinterpret_cast<char *> (trace[i]) -
                    reinterpret_cast<char *> (dlinf.dli_fbase)),
                    color_output_, &memory);
        }

        char *function_name_end = strstr(line, "\n");
        if (function_name_end != NULL) {
            *function_name_end = 0;
            {
                // "\033[34;1m[%s]\033[0m \033[33;1m(%i)\033[0m\n
                char* msg = memory;
                const int msg_max_length = 512;
                if (color_output_) {
                    strcpy(msg, "\033[34;1m"); // NOLINT(runtime/printf)
                } else {
                    msg[0] = 0;
                }
                strcat(msg, "["); // NOLINT(runtime/printf)
                strcat(msg, line); // NOLINT(runtime/printf)
                strcat(msg, "]"); // NOLINT(runtime/printf)
                if (append_pid_) {
                    if (color_output_) {
                        strcat(msg, "\033[0m\033[33;1m"); // NOLINT(runtime/printf)
                    }
                    strcat(msg, " ("); // NOLINT(runtime/printf)
                    strcat(msg, Safe::itoa(getppid(), msg + msg_max_length)); // NOLINT(*)
                    strcat(msg, ")"); // NOLINT(runtime/printf)
                    if (color_output_) {
                        strcat(msg, "\033[0m"); // NOLINT(runtime/printf)
                    }
                    strcat(msg, "\n"); // NOLINT(runtime/printf)
                } else {
                    if (color_output_) {
                        strcat(msg, "\033[0m"); // NOLINT(runtime/printf)
                    }
                    strcat(msg, "\n"); // NOLINT(runtime/printf)
                }
                print(msg);
            }
            line = function_name_end + 1;

            // Remove the common path root
            if (cut_common_path_root_) {
                int cpi;
                for (cpi = 0; cwd[cpi] == line[cpi]; cpi++) {
                };
                if (line[cpi - 1] != '/') {
                    for (; line[cpi - 1] != '/'; cpi--) {
                    };
                }
                if (cpi > 1) {
                    line = line + cpi;
                }
            }

            // Remove relative path root
            if (cut_relative_paths_) {
                char *path_cut_pos = strstr(line, "../");
                if (path_cut_pos != NULL) {
                    path_cut_pos += 3;
                    while (!strncmp(path_cut_pos, "../", 3)) {
                        path_cut_pos += 3;
                    }
                    line = path_cut_pos;
                }
            }

            // Mark line number
            if (color_output_) {
                char* number_pos = strstr(line, ":");
                if (number_pos != NULL) {
                    char* line_number = memory; // 128
                    strcpy(line_number, number_pos); // NOLINT(runtime/printf)
                    // Overwrite the new line char
                    line_number[strlen(line_number) - 1] = 0;
                    // \033[32;1m%s\033[0m\n
                    strcpy(number_pos, "\033[32;1m"); // NOLINT(runtime/printf)
                    strcat(line, line_number); // NOLINT(runtime/printf)
                    strcat(line, "\033[0m\n"); // NOLINT(runtime/printf)
                }
            }
        }

        // Overwrite the new line char
        line[strlen(line) - 1] = 0;

        // Append pid
        if (append_pid_) {
            // %s\033[33;1m(%i)\033[0m\n
            strcat(line, " "); // NOLINT(runtime/printf)
            if (color_output_) {
                strcat(line, "\033[33;1m"); // NOLINT(runtime/printf)
            }
            strcat(line, "("); // NOLINT(runtime/printf)
            strcat(line, Safe::itoa(getppid(), memory)); // NOLINT(runtime/printf)
            strcat(line, ")"); // NOLINT(runtime/printf)
            if (color_output_) {
                strcat(line, "\033[0m"); // NOLINT(runtime/printf)
            }
        }

        strcat(line, "\n"); // NOLINT(runtime/printf)
        print(line);
    }

    // Write '\0' to indicate the end of the output
    char end = '\0';
    write(STDERR_FILENO, &end, 1);

#elif defined(__APPLE__)
    for (int i = 0; i < trace_size; i++) {
        Safe::ptoa(trace[i], memory);
        strcat(memory, "\n");
        print(memory);
    }
#endif
    if (thread_safe_) {
        // Resume the parent process
        kill(getppid(), SIGCONT);
    }

    // This is called in the child process
    _Exit(EXIT_SUCCESS);
}

#if (__GNUC__ > 4) || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6)
#pragma GCC diagnostic pop
#endif
#ifdef __clang__
#pragma clang diagnostic pop
#endif

#endif  // DEATH_HANDLER_H_

#else

class DeathHandler {
};

#endif