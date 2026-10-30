#!/usr/bin/env python3
"""
Smart NEORV32 uploader: waits for CMD:> prompt then uploads.
Usage: python3 smart_upload.py <serial_port> <neorv32_exe.bin>
"""
import sys, serial, time

if len(sys.argv) != 3:
    print(f"Usage: {sys.argv[0]} <port> <exe.bin>")
    sys.exit(1)

port, exefile = sys.argv[1], sys.argv[2]

with open(exefile, 'rb') as f:
    data = f.read()

print(f"Opening {port}...", flush=True)
ser = serial.Serial(port, baudrate=19200, timeout=1)

# Drain any pending data
time.sleep(0.3)
ser.reset_input_buffer()

# Send SPACE every 0.4s to abort auto-boot countdown (max 15s)
# Bootloader auto-boot is 8s; spaces abort it at any point.
print("Waiting for CMD:> prompt (aborting auto-boot)...", flush=True)
buf = b''
deadline = time.time() + 15
last_space = 0
while time.time() < deadline:
    now = time.time()
    if now - last_space > 0.4:
        try:
            ser.write(b' ')
        except Exception:
            pass
        last_space = now
    try:
        chunk = ser.read(ser.in_waiting or 1)
    except Exception:
        chunk = b''
    if chunk:
        buf += chunk
        sys.stdout.write(chunk.decode('ascii', errors='replace'))
        sys.stdout.flush()
    if b'CMD:>' in buf:
        buf = b''  # reset buf so we don't false-match later
        break

if b'CMD:>' not in buf and b'CMD:>' not in b'':
    print("\nReady (CMD:> seen or timeout — proceeding)")

# Send 'u' to enter upload mode
print("\nSending 'u' to start upload...", flush=True)
ser.write(b'u')
time.sleep(0.8)
ser.reset_input_buffer()

# Send binary
print(f"Uploading {len(data)} bytes...", flush=True)
ser.write(data)

# Wait for OK or ERROR
buf = b''
deadline = time.time() + len(data) // (19200 // 10) + 15
while time.time() < deadline:
    try:
        chunk = ser.read(ser.in_waiting or 1)
    except Exception:
        chunk = b''
    if chunk:
        buf += chunk
        sys.stdout.write(chunk.decode('ascii', errors='replace'))
        sys.stdout.flush()
    if b'OK' in buf:
        break
    if b'ERROR' in buf:
        break

if b'OK' in buf:
    print("\nUpload OK! Starting executable...")
    ser.write(b'e')

    # Step 1: wait for "Booting from" — confirms bootloader handed off to program.
    # This also flushes the "CMD:> e\r\n" echo from the buffer before we capture output.
    print("--- Program output ---")
    preamble = b''
    deadline = time.time() + 8
    while time.time() < deadline:
        try:
            chunk = ser.read(ser.in_waiting or 1)
        except Exception:
            break
        if chunk:
            preamble += chunk
            if b'Booting from' in preamble:
                break
        else:
            time.sleep(0.05)

    # Step 2: collect actual program output until CMD:> reappears
    out_buf = b''
    try:
        while True:
            try:
                chunk = ser.read(ser.in_waiting or 1)
            except Exception:
                break
            if chunk:
                out_buf += chunk
                sys.stdout.write(chunk.decode('ascii', errors='replace'))
                sys.stdout.flush()
                if b'CMD:>' in out_buf:
                    break  # bootloader restarted — ready for next upload
            else:
                time.sleep(0.05)
    except KeyboardInterrupt:
        pass
    print("\n[Board back at CMD:> — ready for next upload]")
else:
    print("\nUpload FAILED")
    sys.exit(1)
