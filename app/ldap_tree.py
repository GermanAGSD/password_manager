from ldap3.utils.conv import escape_filter_chars
from ldap3 import Server, Connection, ALL, SIMPLE, SUBTREE
from app.settings import settings

LDAP_SERVER = 'ldap://172.30.30.3'
LDAP_BIND_DN = 'CN=my-service,CN=Users,DC=bull,DC=local'
LDAP_PASSWORD = settings.domain_password

from ldap3 import Server, Connection, ALL, SUBTREE

server = Server(LDAP_SERVER, get_info=ALL)
conn = Connection(
    server,
    user="BULL\\my-service",   # или полный DN
    password=LDAP_PASSWORD,
    auto_bind=True
)

base_dn = "OU=Пользователи,DC=bull,DC=local"

conn.search(
    search_base=base_dn,
    search_filter="(objectClass=organizationalUnit)",
    search_scope=SUBTREE,   # рекурсивно, включая вложенные OU
    attributes=["distinguishedName", "ou", "name"]
)

for e in conn.entries:
    print(e.distinguishedName)