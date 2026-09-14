#!/bin/bash
# tar_chmod_only.sh <tar-stderr-file>: exit 0 when every line of tar's stderr
# is the overlayfs chmod refusal ("Cannot change mode", podman 3.4 builds) or
# the summary line tar prints after any error at all; exit 1 when anything else
# is in there (a truncated download, a changed archive layout).
#
# The summary line is the trap: GNU tar ends every failed run with "Exiting
# with failure status due to previous errors", bsdtar with "Error exit delayed
# from previous errors", so a check that only tolerates the chmod line never
# tolerates anything. setup.sh's extract() calls this; test_tar_chmod_only.sh
# holds both tars' real output.
! grep -qEv 'Cannot change mode|Exiting with failure status due to previous errors|Error exit delayed from previous errors' "$1"
