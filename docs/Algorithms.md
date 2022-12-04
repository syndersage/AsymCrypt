## RSA
- For the public key used standard value 65537

## DH
- To make first key exchange step (g^a mod p) input field/file must be empty.
- To make second key exchange step ((g^a)^b mod p) input field/file must contain result of first step (g^a mod p)

## Shamir
- Every key (first/second) of every participant (Alice/Bob) can be used in any order

## ElGamal
- For padding as an option used the same algorithm (from PKCS#1 standard) as in RSA

## MD5, SHA1
- Digest algorithms does not require any parameters
- Max input size - 1GB
- Unlike all other algorithms result returns in HEX

## DSA, ElGamal sign
- In both (Sign, Verify) - input field is digest of message (not signed digest)
- "Move output to input" moves result in special fields of "Verify" parameters. DSA - half to "Signed digest part №1", half to "Signed digest part №2". ElGamal sign - "Signed digest". If file input was used - you need to specify these values manually
- To conclude that the signature is correct compare result with one of specific parameter fields. DSA - "Signed digest part №1". ElGamal sign - "Required verification output". If output and specific parameter are the same - signature is valid, otherwise - incorrect
