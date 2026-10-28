/* iOS SDK hides fork declarations from app-store applications. This owner
 * development platform supplies the actual Darwin fork/vfork syscalls. */
#define fork zeta_sdk_unavailable_fork
#define vfork zeta_sdk_unavailable_vfork
#include <unistd.h>
#undef fork
#undef vfork
extern pid_t fork(void);
extern pid_t vfork(void);
