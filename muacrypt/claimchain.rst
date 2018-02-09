
WORK-in-PROGRESS

out of band verification protocol
---------------------------------

Terms:

- "peer" someone i exchanged messages with

- "msgid", message id from MIME header of e-mail


Send history information to peer
---------------------------------

- ``peeraddr`` the address of the peer we are doing OOB verification with

1. collect a list ``OUT_HISTORY`` of ``(DATE, msgid, finger_print)`` tuples
   for my own messages to a peer.

2. collect a list ``IN_HISTORY`` of ``(DATE, From, msgid, peer_fingerprint)`` tuples
   for each message where ``peeraddr`` was one of the specified message participants
   (contained in any of From, To, CC headers). ``From`` is either ``peeraddr``
   in which case the peer_fingerprint was sent directly, and otherwise indicates
   from which address we saw an ``AUTOCRYPT-GOSSIP`` header.

3. collect a list ``OOB_VERIFICATIONS`` of ``(DATE, peeraddr, peer_fingerprint)``
   for all out-of-band verifications with peers which were involved in messages
   of both myaddr and peeraddr.

4. send ``(myadr, peeraddr, OUT_HISTORY, IN_HISTORY, OOB_VERIFICATIONS)``
   to the peer via an oob-channel.

Process history information from a peer
---------------------------------------

We get::

    (peeraddr, myadr, OUT_HISTORY, IN_HISTORY, OOB_VERIFICATIONS)

1. check that peeaddr is used with the account, if not,
   signal user mismatch error (should not happen if the oob-channel
   is setup properly, so maybe more an internal error, to be debugged)

2. check that each message from our peer's ``OUT_HISTORY`` exists
   in our particular ``peerlog`` and matches wrt to received finger_print.
   in particular:

   - If a message has a different finger_print then signal
     MITM-ATTACK to the user, referencing/citing the offending message.

   - If we don't know of a message and its DATE is newer than our
     earliest ``peerlog`` message, emit a DROPPED-MESSAGE-WARNING.

3. check that each message in our peer's ``IN_HISTORY`` exists
   in our ``peerlog``.

   - If a message has a different finger_print then signal
     MITM-ATTACK to the user, referencing/citing the offending message.

   - If we don't know of a message and its DATE is newer than our
     earliest ``peerlog`` message, emit a DROPPED-MESSAGE-WARNING.

4. check that each oob verification is consistent with our notes.

   for (DATE, peer_addr, peer_fingerprint) in the OOB_VERIFICATIONS:

    - if we have a message before and after that date from that peer
      and both messages have the same fingerprint but it differs from
      we get through peer_fingerprint, signal MITM-ATTACK error.

    - if an oob verification for a peeraddr and DATE does not match
      the fingerprint of the earlierst both the a
