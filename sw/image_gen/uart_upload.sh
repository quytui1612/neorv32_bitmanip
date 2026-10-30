#!/usr/bin/env bash

# Simple script to upload an executable to the default NEORV32 bootloader

set -e

# Default baud rate
BAUD=19200

# check arguments; show help text
if [ $# -ne 2 ]
then
  printf "Upload an executable via serial port (UART) to the NEORV32 bootloader.\n"
  printf "If the upload is successful, the executable will be run automatically.\n"
  printf "Reset processor before starting the upload.\n\n"
  printf "Usage:   ./uart_upload.sh <serial port> <NEORV32 executable>\n"
  printf "Example: ./uart_upload.sh /dev/ttyS6 path/to/neorv32_exe.bin\n"
  exit 0
fi

# timeout to wait for bootloader "OK" response after upload
# "BAUD" bits per second; 10 bits per byte (incl START and STOP bits); plus margin for bootloader processing
FILESIZE=$(stat -c%s "$2")
TIMEOUT=$(( (FILESIZE / (BAUD/10)) + 5 ))
[ $TIMEOUT -lt 5 ] && TIMEOUT=5

# setup serial port
printf "Opening serial port ($1)... "
stty -F $1 $BAUD -hup raw -echo cs8 -cstopb -ixon clocal cread
exec 3<>$1
printf "OK\n"

# send executable
printf "Uploading executable ($FILESIZE bytes)... "
printf " u" >&3 # skip auto-boot (SPACE) and start upload ('u')
# give bootloader time to print "Awaiting ..." and enter upload mode before sending binary
sleep 1
cat $2 >&3 # send executable

# wait for upload to complete and check bootloader response
UPOLOAD_OK=0
EXPIRED=$(( SECONDS + TIMEOUT ))
PATTERN="OK"
PATTERN_ERR="ERROR"
BUFFER=""
while [ $SECONDS -lt $EXPIRED ]; do
  if read -r -n 1 -u 3 -t 1 CH; then
    BUFFER+=$CH
    UPOLOAD_OK=-1
    if [[ "$BUFFER" == *"$PATTERN"* ]]; then
      UPOLOAD_OK=1
      break
    fi
    if [[ "$BUFFER" == *"$PATTERN_ERR"* ]]; then
      printf "\nBootloader reported error (response: %s)\n" "$BUFFER" >&2
      break
    fi
  fi
done

if [ $UPOLOAD_OK -eq 1 ]; then
  printf "OK\n" >&2
elif [ $UPOLOAD_OK -eq -1 ]; then
  printf "\nERROR! Invalid bootloader response (got: %s).\n" "$BUFFER" >&2
else
  printf "\nERROR! Bootloader response timeout ($TIMEOUT seconds).\n" >&2
  printf "Tip: Try the OTHER serial port (e.g. /dev/ttyUSB0 vs /dev/ttyUSB1). Reset board, then run upload again.\n" >&2
fi

# start executable
if [ $UPOLOAD_OK -eq 1 ]; then
  printf "Booting executable...\n"
  printf "e" >&3
fi

# done
exec 3>&-
if [ $UPOLOAD_OK -eq 1 ]; then
  exit 0
else
  printf "Check configuration, reset processor and try again.\n" >&2
  exit 1;
fi
