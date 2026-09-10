"""LDAP injection fixture — must be detected."""
from ldap3 import Connection


def search_user(conn, username):
    search_filter = f"(uid={username})"
    conn.search("ou=users,dc=example,dc=com", search_filter)


def search_build(conn, name):
    base_filter = "(&(objectClass=person)(cn="
    search_filter = base_filter + name + "))"
    conn.search("ou=users,dc=example,dc=com", search_filter)
