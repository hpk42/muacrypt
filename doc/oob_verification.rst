
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

2. collect a list ``IN_HISTORY`` of ``(DATE, origin_addr, msgid, peer_fingerprint)`` tuples
   for each message where ``peeraddr`` was one of the specified message participants
   (contained in any of From, To, CC headers). If ``origin_addr == peer_addr`` then
   the key was sent directly, otherwise it was gossiped from another peer
   through an ``AUTOCRYPT-GOSSIP`` header.

3. collect a list ``OOB_VERIFICATIONS`` of ``(peer_addr, peer_fingerprint)``
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

4. add a verification block which contains:

   - origin=peer_addr0 to tell where we
   - origin_auth=peer_fingerprint
   - origin_date=CURRENT_DATE
   - OOB_VERIFICATIONS


Determining OOB_VERIFICATIONs
-----------------------------

Go through all verification blocks and incoming messages
to perform or recommend verification actions. The output
of this algorithm is a map of peer_addr -> score entries.
We call each score also the "peer_score".

If a score for a peer_addr is higher, it is placed
higher on the "to be oob-verified recommendation" list.

1. "complete match"
  We set peer_score to "0" (green, perfect)
  where for each key we saw for the peer,
  we have a matching oob verification.
  additional oob verification are ignored for scoring
  because they might relate to message history from that peer
  that we don't have.

2. "unverified keys"
  If we have keys for a peer which don't have a
  matching OOB_VERIFICATION, compute the score
  as "OOB_UNVERIFIED_KEY_WEIGHT / AGE_LAST_MSG" where AGE_LAST_MSG
  indicates the time since we last a message with an unverified key.

  TODO: increase the weight further if we had past messages
  with an oob-verified key, but recent messages with an unverified one?

3. If we have seen different keys in gossip than in direct
  messages from a peer, add OOB_KEY_MISMATCH / AGE_MISMATCH
  to peer_score where AGE_MISMATCH is the time difference
  between the latest two dates of conflicting messages.

