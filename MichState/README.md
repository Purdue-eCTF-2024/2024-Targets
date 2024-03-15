# Michigan State

The michigan state has some sort of tls like handshake with manufacture certificates and an elliptic curve diffie helman key exchange.

Problems:
- The post boot is encrypted with chacha20poly1305, but no protection against replay attacks
- It seems to boot 1 component fully and print it's boot message before verifying the next component
- CMU got all the attest flags first, so there might be an easier to find vulnerability when the ap asks component for attest data
