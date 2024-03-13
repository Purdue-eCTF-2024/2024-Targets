## Target Notes

They are basically the reference design with a few modifications:
Buffer overflow fixed
- They have this thing called component token which is a random number generated at build time, shared between all components. When ap asks component to boot, it asks for the component token, and won't boot unless the component token is correct. 
  - This is easily bypassable though since you can just ask a valid component for it token, and send ap that token
- The post boot messaging is encrypted with chacha20poly1305, but there are still no nonces or anything, so it is easy to just do a replay attack
 
All the other things like attestation data leak and component boot can basically be solved the same way as reference design

>DeltaForce
