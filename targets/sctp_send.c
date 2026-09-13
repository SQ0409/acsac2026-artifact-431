/* Compatibility name retained for readers of the original command line.
 * This target deliberately performs no networking: the -N endpoint is
 * the sole SCTP path. It exits immediately so it cannot block the dry
 * run while waiting for input. Replace it with any suitable executable.
 */
int main(void) {
  return 0;
}
