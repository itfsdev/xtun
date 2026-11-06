package org.amnezia.xtun;

public class XtunException extends RuntimeException {
    public static final int LIBXTUN_OK = 0;
    public static final int LIBXTUN_ERR_INVALID_ARGS = -1;
    public static final int LIBXTUN_ERR_UNSUPPORTED = -2;
    public static final int LIBXTUN_ERR_DRIVER_UNAVAILABLE = -3;
    public static final int LIBXTUN_ERR_DEVICE_CREATE = -4;
    public static final int LIBXTUN_ERR_KILLSWITCH = -5;
    public static final int LIBXTUN_ERR_SYSTEM = -6;
    public static final int LIBXTUN_ERR_DNS = -7;
    public static final int LIBXTUN_ERR_SPLIT_BUSY = -8;
    public static final int LIBXTUN_ERR_ACCESS_DENIED = -9;
    public static final int LIBXTUN_ERR_SPLIT_DRIVER = -10;

    public static final int LIBXTUN_ERR_JNI_NOMEM = -10000;
    public static final int LIBXTUN_ERR_JNI_WRONG_PARAM = -10001;
    public static final int LIBXTUN_ERR_JNI_CLOSED = -10002;

    private final int code;

    public XtunException(int code) {
        super(describe(code));
        this.code = code;
    }

    public int code() {
        return code;
    }

    private static String describe(int code) {
        switch (code) {
            case LIBXTUN_ERR_JNI_NOMEM:
                return "JNI: out of memory";
            case LIBXTUN_ERR_JNI_WRONG_PARAM:
                return "JNI: wrong parameter";
            case LIBXTUN_ERR_JNI_CLOSED:
                return "JNI: the instance is closed";
            default:
                return nativeDescribe(code);
        }
    }

    private static native String nativeDescribe(int code);
}
