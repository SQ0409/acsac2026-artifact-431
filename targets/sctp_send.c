#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
/* Compatibility name retained for readers of the original command line.
 * This target deliberately performs no networking: AFLNet's -N endpoint is
 * the sole SCTP path. Replace this file with any executable for a deployment.
 */
#include <unistd.h>
int main(void) {
  unsigned char buf[4096];
  while (read(STDIN_FILENO, buf, sizeof(buf)) > 0) { }
  return 0;
}
