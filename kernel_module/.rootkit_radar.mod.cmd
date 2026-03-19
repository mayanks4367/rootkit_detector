savedcmd_rootkit_radar.mod := printf '%s\n'   rootkit_radar.o | awk '!x[$$0]++ { print("./"$$0) }' > rootkit_radar.mod
