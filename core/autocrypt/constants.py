
import os.path


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

NOPREFERENCE = 'nopreference'
MUTUAL = 'mutual'


AC = 'Autocrypt'
ADDR = 'addr'
KEYDATA = 'keydata'
PE = 'prefer-encrypt'

PE_HEADER_TYPES = [None, NOPREFERENCE, MUTUAL]

AC_HEADER_PE = "addr=%(addr)s; prefer-encrypt=%(pe)s; keydata=%(keydata)s"
AC_HEADER = "addr=%(addr)s; keydata=%(keydata)s"

AC_GOSSIP = 'Autocrypt-Gossip'
AC_GOSSIP_HEADER = "addr=%(addr)s; keydata=%(keydata)s"

RESET = 'reset'
GOSSIP = 'gossip'

OWN_STATE = 'own_state'
SECRET_KEY = 'secret_key'
PUBLIC_KEY = 'public_key'
PREFER_ENCRYPT = 'prefer_encrypt'

ACCOUNT_PE_TYPES = [NOPREFERENCE, MUTUAL]

PEER_STATE = 'peer_state'
LAST_SEEN = 'last_seen'
LAST_SEEN_AC = 'last_seen_autocrypt'
STATE = 'state'

RESET = 'reset'
GOSSIP = 'gossip'

PEER_STATE_TYPES = [NOPREFERENCE, MUTUAL, RESET, GOSSIP]

CERTIFICATE = 'certificate'

RECOMMENDATION = 'recommendation'

DISABLE = 'disable'
DISCOURAGE = 'discourage'
AVAILABE = 'available'
ENCRYPT = 'encrypt'

AC_PREFER_ENCRYPT_HEADER = 'Autocrypt-Prefer-Encrypt: '
AC_SETUP_MSG = 'Autocrypt-Setup-Message: '
LEVEL_NUMBER = 'v1'
AC_SETUP_MSG_HEADER = AC_SETUP_MSG + LEVEL_NUMBER
AC_CT_SETUP = 'application/autocrypt-setup'
