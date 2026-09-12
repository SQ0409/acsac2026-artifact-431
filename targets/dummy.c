/*
 * Optional smoke target. AFLNet sends traffic using -N; this executable is
 * only a harmless process target so the command line is easy to exercise.
 * Replace it with any executable appropriate for your environment.
 */
#include <unistd.h>

int main(void) {
  unsigned char buf[4096];
  while (read(STDIN_FILENO, buf, sizeof(buf)) > 0) { }
  return 0;
}
