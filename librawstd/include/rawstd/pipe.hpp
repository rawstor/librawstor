#ifndef RAWSTD_PIPE_HPP
#define RAWSTD_PIPE_HPP

namespace rawstd {

/**
 * A non-blocking pipe(2), RAII-owned: creates both ends (O_NONBLOCK) in
 * the constructor, throwing std::system_error on failure, and closes
 * whichever end(s) are still owned in the destructor. Move-only.
 *
 * The read and write ends are frequently owned by different objects with
 * different lifetimes -- e.g. a self-pipe used to wake a rawio reactor
 * from a signal handler (write(2) is async-signal-safe) typically has
 * the write end held for the process's whole lifetime while the read end
 * is handed off to whatever will consume it via its own rawio_read().
 * release_read()/release_write() give up ownership of just one end
 * (without closing it) for exactly that split; the whole-object move
 * constructor/assignment cover the common case of moving both ends
 * together instead.
 */
class Pipe final {
private:
    int _read_fd;
    int _write_fd;

public:
    Pipe();
    Pipe(const Pipe&) = delete;
    Pipe(Pipe&& other) noexcept;
    ~Pipe();

    Pipe& operator=(const Pipe&) = delete;
    Pipe& operator=(Pipe&& other) noexcept;

    inline int read_fd() const noexcept { return _read_fd; }

    inline int write_fd() const noexcept { return _write_fd; }

    /**
     * Gives up ownership of the read end without closing it -- the
     * caller now owns it. Subsequent read_fd() returns -1.
     */
    int release_read() noexcept;

    /**
     * Gives up ownership of the write end without closing it -- the
     * caller now owns it. Subsequent write_fd() returns -1.
     */
    int release_write() noexcept;
};

} // namespace rawstd

#endif // RAWSTD_PIPE_HPP
