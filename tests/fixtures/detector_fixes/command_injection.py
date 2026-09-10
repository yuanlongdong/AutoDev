"""Command injection fixtures — must be detected."""
import subprocess
import os


def run_check_output(user_input):
    result = subprocess.check_output(user_input, shell=True)
    return result


def run_check_call(user_input):
    subprocess.check_call(user_input, shell=True)


def run_getoutput(user_input):
    out = subprocess.getoutput(f"echo {user_input}")
    return out


def run_system(user_input):
    os.system(user_input)
