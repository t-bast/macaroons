# Macaroons

This library implements macaroons as described in the paper
["Macaroons: Cookies with Contextual Caveats for Decentralized Authorization in the Cloud"](https://research.google/pubs/pub41892/).

It uses HMAC-SHA256 and AES-GCM.

This is a work-in-progress and **should not be used in production**.

## TODO

- [ ] Add hooks to plug validation of first-party caveats based on some request context
