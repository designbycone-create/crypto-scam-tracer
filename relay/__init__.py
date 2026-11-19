"""Phone app relay: the ScamHunter Threat Desk app reaches this Desk through the user's own Cloudflare Worker.

    phone app  --HTTPS-->  your Worker  <--WebSocket (outbound from this PC)--  Desk  -->  127.0.0.1

The Desk opens the connection to the Worker, so nothing on this computer listens to the internet.
Every request and response is encrypted end to end (AES-256-GCM) with a key that only the Desk and
the paired phone have (shared once by QR code). The Worker passes along ciphertext it can't read.
See relay/PROTOCOL.md.
"""
