# Target executable

`dummy` is a no-op smoke target. `sctp_send` is an equivalent compatibility name for the command shown in the paper notes. AFLNet's `-N` option owns SCTP communication; neither target is a proxy or opens a second network path. Both exit immediately instead of reading standard input, so they cannot block AFLNet's dry run. Replace either with any executable suitable for the reviewer's setup.
