SMCAA notes:
- They have this md5 challenge response, md5 is obviously not optimal, maybe it can be broken, im not super familar with that though
- Post boot messages are hashed with the secret and md5, but there is no protection against replay attack
- We can get it to boot with a fake component by just using the other component to answer the md5 challenge response, this won't mess up boot state of that component, since the boot command is seprate from the validate command, and validate is run first
- Attestation data is not encrypted, we can snoop the i2c bus in supply chain
- Attesting and booting and everything uses only 1 md5 secret per deployment, so we can get attest data without the pin in scenario 1 by just asking another component to hash the nonce for us
- Black box boot and attest can be achieved by putting the black box image on 2 boards and using 1 board to answer the other board's md5 challenges
