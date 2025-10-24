import subprocess
import time
import signal
import pytest

@pytest.fixture(scope="session", autouse=True)
def buggy_app():
    """
    Start the vulnerable Flask app (buggy.py) as a subprocess
    before tests, and terminate it afterward.

    Chat-GPT helped a LOT here!
    """
    # Start the app
    proc = subprocess.Popen(
        ["python", "buggy_app/buggy.py"],  # adjust path if needed
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        preexec_fn=lambda: signal.signal(signal.SIGINT, signal.SIG_IGN),
    )

    # Wait for the server to start
    time.sleep(2)

    yield  # run the tests

    # Teardown
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
