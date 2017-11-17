from email import policy, encoders
from email.mime import MIMEMultipart, MIMEApplication, MIMEText
from emailpgp.mime import MIMEMultipartPGP

from .constants import AC_SETUP_TEXT, AC_CT_SETUP


class MIMEMultipartACSetup(MIMEMultipart):
    """
    Base class for MIME multipart/mixed including application/autocrypt-setup.
    """

    def __init__(self, _data=None, _subtype='mixed', boundary=None,
                 *, policy=policy.default, **_params):
        """Creates a multipart/mixed type message containing
        application/autocrypt-setup.

        By default, creates a multipart/mixed message, with proper
        Content-Type and MIME-Version headers.

        _subtype is the subtype of the multipart content type, defaulting to
        `mixed'.

        boundary is the multipart boundary string.  By default it is
        calculated as needed.

        _data is a string containing the raw payload data (encrypted).

        Additional parameters for the Content-Type header are taken from the
        keyword arguments (or passed into the _params argument).

        It will create the Email structure:
        └┬╴multipart/mixed
         ├─╴text/plain
         └─╴application/autocrypt-setup attachment [autocrypt-setup-message.html]

         """
        # _params['protocol'] = "?"
        description = MIMEApplicationACSetupDescription()
        payload = MIMEApplicationACSetupPayload(_data)
        _subparts = [description, payload]
        MIMEMultipart.__init__(self, _subtype, boundary, _subparts,
                               policy=policy, **_params)


class MIMEApplicationACSetupPayload(MIMEApplication):
    """Class for generating application/autocrypt-setup MIME documents."""

    def __init__(self, _data,
                 _subtype=AC_CT_SETUP,
                 _encoder=encoders.encode_noop, *, policy=None, **_params):
        """Create an application/autocrypt-setup type MIME document.

        _data is a string containing the raw application data.

        _subtype is the MIME content type subtype, defaulting to
        'autocrypt-setup; name="autocrypt-setup-message.txt"'.

        _encoder is a function which will perform the actual encoding for
        transport of the application data, defaulting to noop encoding.

        Any additional keyword arguments are passed to the base class
        constructor, which turns them into parameters on the Content-Type
        header.
        """
        _params["Content-Description"] = "Autocrypt Setup Message key"
        _params["Content-Disposition"] = 'attachment; filename="autocrypt-setup-message.txt"'
        # _params["Content-Disposition"] = 'attachment; filename="autocrypt-setup-message.html"'
        MIMEApplication.__init__(self, _data, _subtype, _encoder,
                                 policy=policy, **_params)


class MIMEApplicationACSetupDescription(MIMEText):
    """Class for generating text/plain MIME documents."""

    def __init__(self, _data=AC_SETUP_TEXT, _subtype='plain',
                 _encoder=encoders.encode_noop, *, policy=None, **_params):
        """Create an text/plaind type MIME document.

        _data is a string containing by default Version: 1\n.

        _subtype is the MIME content type subtype, defaulting to
        'pgp/encrypted'.

        _encoder is a function which will perform the actual encoding for
        transport of the application data, defaulting to noop encoding.

        Any additional keyword arguments are passed to the base class
        constructor, which turns them into parameters on the Content-Type
        header.
        """
        _params["Content-Description"] = "Autocrypt Setup Message description"
        MIMEApplication.__init__(self, _data, _subtype, _encoder,
                                 policy=policy, **_params)
