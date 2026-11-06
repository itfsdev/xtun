#include <xtun.h>

extern "C" const char *libxtun_strerror(int error)
{
    switch (static_cast<libxtun_error>(error)) {
    case LIBXTUN_OK: return "ok";
    case LIBXTUN_ERR_INVALID_ARGS: return "invalid args";
    case LIBXTUN_ERR_UNSUPPORTED: return "operation not supported";
    case LIBXTUN_ERR_DRIVER_UNAVAILABLE: return "tun device driver unavailable";
    case LIBXTUN_ERR_DEVICE_CREATE: return "failed to create tun device";
    case LIBXTUN_ERR_KILLSWITCH: return "killswitch error";
    case LIBXTUN_ERR_SYSTEM: return "system error";
    case LIBXTUN_ERR_DNS: return "dns error";
    case LIBXTUN_ERR_SPLIT_BUSY: return "split-tunnel driver is busy";
    case LIBXTUN_ERR_ACCESS_DENIED: return "access denied";
    case LIBXTUN_ERR_SPLIT_DRIVER: return "split-tunnel driver error";
    case LIBXTUN_ERR_RESERVED_0:
    case LIBXTUN_ERR_RESERVED_1:
    case LIBXTUN_ERR_RESERVED_2:
    case LIBXTUN_ERR_RESERVED_3:
    case LIBXTUN_ERR_RESERVED_4:
    case LIBXTUN_ERR_RESERVED_5:
    case LIBXTUN_ERR_RESERVED_6:
    case LIBXTUN_ERR_RESERVED_7:
    case LIBXTUN_ERR_RESERVED_8:
    case LIBXTUN_ERR_RESERVED_9: return "reserved";
    }
    return "unknown error";
}
