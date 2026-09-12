/* Optional libcap compatibility for unprivileged artifact builds. */
#ifndef ARTIFACT_SYS_CAPABILITY_H
#define ARTIFACT_SYS_CAPABILITY_H
typedef int cap_value_t;
typedef int cap_flag_value_t;
typedef void *cap_t;
#define CAP_SYS_ADMIN 21
#define CAP_EFFECTIVE 0
#define CAP_PERMITTED 1
#define CAP_SET 1
static inline cap_t cap_get_file(const char *path) { (void)path; return 0; }
static inline cap_t cap_get_proc(void) { return 0; }
static inline int cap_get_flag(cap_t c, cap_value_t v, int f,
                               cap_flag_value_t *out) {
  (void)c; (void)v; (void)f; if (out) *out = 0; return 0;
}
#endif
