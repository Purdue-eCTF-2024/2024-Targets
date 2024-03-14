## Target Notes

They are basically the reference design with a few modifications:
- Buffer overflow fixed
- They have this thing called component token which is a random number generated at build time, shared between all components. When ap asks component to boot, it asks for the component token, and won't boot unless the component token is correct. 
  - This is easily bypassable though since you can just ask a valid component for it token, and send ap that token
- There is also an ap token. Whenever the ap sends a command to the component, it sends this token and the component checks it is correct before doing anything else related to the command
  - It is easy to just get this token form the ap by performing list or something and snooping it off i2c. The only problem is in black box boot, there is no ap, it will be hard to by pass the token check.
- The post boot messaging is encrypted with chacha20poly1305, but there are still no nonces or anything, so it is easy to just do a replay attack

>DeltaForce
