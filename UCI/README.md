# Key Exchange

so everything sent in plaintext is:
- k2 ^ random1
- k2 ^ random2
- k1 ^ M
- k3 ^ M
- k3 ^ F ^ random1
- k1 ^ F ^ random2

Final key K = k1 ^ k2 ^ k3

# Possible things to get

(k2 ^ r1) ^ (k2 ^ r2) = r1 ^ r2
(k1 ^ M) ^ (k3 ^ M) = k1 ^ k3
M ^ F ^ r1
M ^ F ^ r2
k2 ^ M ^ F

couldn't think of how to get k2 into the xor

a ^ b ^ k1 ^ F


To break in valid ap and components scenario:

k3 ^ F ^ r2
M ^ F ^ r2

ap in 3rd round sends out our input L ^ M ^ F ^ r1
in the first input we seond 0
in the other input we send (r1 ^ r2 ^ k3 ^ M) (where k3 ^ M is known from a previous round)

k3 ^ F ^ r2

k2 ^ M ^ F
k1 ^ k2 ^ F
k3 ^ k2 ^ F

k1 ^ k2 ^ k3 ^ M ^ F
k2 ^ k3 ^ F
k2 ^ k1 ^ F

r1 ^ k3 ^ F
r1 ^ M ^ F





ap will send:
- M ^ F ^ r2
- k1 ^ M ^ M ^ F ^ r2


we can send out other components key, so say ap gets k1 ^ M twice

know (r1 ^ r2) after first round

lets say we seond (k1 ^ k3) from a prior round of observing

ap thinks k1 is k1 but it is actualy (k1 ^ k3)

it will send (k1 ^ k3 ^ M ^ F ^ r2)
we can do (k1 ^ k3 ^ M ^ F ^ r2) ^ (k1 ^ k3) ^ current round (r1 ^ r2) = (M ^ F ^ r1)
This alows recovering k3: (k3 ^ F ^ r1) ^ (F ^ r1) = k3
a similar trick can be used for k1

M can be recovered


