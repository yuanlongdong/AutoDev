"""Round-8 insecure SSH host-key policy fixture (paramiko)."""
import paramiko


def connect_ssh_insecure(host, username, password):
    """BAD: unknown SSH host keys are auto-accepted (MITM)."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, username=username, password=password)
    return client


def connect_ssh_safe(host, username, password):
    """GOOD: unknown host keys are rejected."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    client.connect(host, username=username, password=password)
    return client
