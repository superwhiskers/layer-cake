# bubblebox

bubblebox is a sandboxing library designed to act as a "sandboxed
`fork(2)`". compared to other sandboxing libraries, bubblebox is able
to run in-process regardless of number of threads. this is important
because `fork(2)`, `clone(2)`, `clone3(2)`, and other mechanisms for
creating a new child process have [stringent restrictions] that are often
overlooked. bubblebox achieves this by owning the syscall surface through
its sibling library, meowix, and avoiding use of the rust standard library
and other crates that rely upon the standard library in the guest path.

other features provided by bubblebox include:

- optional cgroups v2 support
  - complete with automatic hierarchy acquisition from systemd
  - as well as support for a caller-provided cgroups hierarchy
- sane typed rlimit management
- scheduler settings, kernel keyring management
  - ensure the state of the guest process is exactly as you want it
- full kernel namespace support
  - mount, user, cgroup, pid, ipc, network, *time* namespaces are all supported
  - and they may be configured through bubblebox. only mount, user, cgroup, and
    pid namespaces are non-optional for stronger guarantees
- mount tree management
- seccomp support
- file descriptor management
- very strong lifetime control
  - spawning a process gives you a `Guest` handle to it. dropping it kills the
    process. if your host process dies, it is also killed. there is no situation
    in which your host dies but the guest doesn't
  - this is accomplished through `CLONE_PIDFD_AUTOKILL`, only introduced in
    linux 7.1
- reasonably sane defaults
- even more!

in the future, bubblebox will support platforms other than linux. currently
planned are:

- windows
  - using appcontainers, other mechanisms
- macos
  - seatbelt, rlimit

[stringent restrictions]: https://www.man7.org/linux/man-pages/man2/fork.2.html#:~:text=After%20a%20fork%28%29%20in%20a%20multithreaded%20program%2C%20the%20child%20can%20safely%20call%20only%20async%2Dsignal%2Dsafe%20functions%20%28see%20signal%2Dsafety%287%29%29%20until%20such%20time%20as%20it%20calls%20execve%282%29%2E
