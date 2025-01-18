#define LOGLEVEL 3

#if LOGLEVEL > 3
#define LOG_DEBUG(...) printf(__VA_ARGS__)
#define FLOG_DEBUG(...) fprintf(__VA_ARGS__)
#else
#define LOG_DEBUG(...)
#define FLOG_DEBUG(...)
#endif

#if LOGLEVEL > 2
#define LOG_INFO(...) printf(__VA_ARGS__)
#define FLOG_INFO(...) fprintf(__VA_ARGS__)
#else
#define LOG_INFO(...)
#define FLOG_INFO(...)
#endif
