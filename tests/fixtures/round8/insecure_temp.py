"""Round-8 insecure temporary file fixture."""
import os
import tempfile
from datetime import datetime


def create_predictable_temp(data):
    """BAD: predictable /tmp filename interpolating pid + timestamp."""
    path = f"/tmp/upload_{os.getpid()}_{datetime.now().timestamp()}.tmp"
    with open(path, "wb") as f:
        f.write(data)
    return path


def create_shared_temp(data):
    """BAD: file made world-writable via chmod 0o777."""
    path = "/tmp/shared_data.txt"
    with open(path, "w") as f:
        f.write(data)
    os.chmod(path, 0o777)
    return path


def create_temp_safe(data):
    """GOOD: tempfile.mkstemp() creates an unpredictable, mode-0600 file."""
    fd, path = tempfile.mkstemp(prefix="upload_")
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    return path
