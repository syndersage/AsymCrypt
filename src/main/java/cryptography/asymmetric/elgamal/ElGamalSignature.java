package cryptography.asymmetric.elgamal;

import cryptography.asymmetric.Numbers;
import java.math.BigInteger;
import java.util.Arrays;

public class ElGamalSignature {


  public static byte[] sign(byte[] digest, ElGamalKeys keys) {
    BigInteger intModulus = new BigInteger(keys.modulus);
    BigInteger intGenerator = new BigInteger(keys.base);
    BigInteger intPrivate = new BigInteger(keys.personalPrivateKey);
    BigInteger intDigest = new BigInteger(digest);

    BigInteger randomValue;
    do {
      randomValue = new BigInteger(intModulus.bitLength(), Numbers.random);
    } while (randomValue.compareTo(intModulus.subtract(BigInteger.ONE)) < 0 | randomValue.gcd(intModulus.subtract(BigInteger.ONE)).compareTo(BigInteger.ONE) != 0);

    BigInteger encryptedGenerator = intGenerator.modPow(randomValue, intModulus);

    BigInteger inverseRandom = randomValue.modInverse(intModulus.subtract(BigInteger.ONE));

    BigInteger encryptedMessage = inverseRandom.multiply(intDigest.subtract(intPrivate.multiply(encryptedGenerator)).mod(intModulus.subtract(BigInteger.ONE))).mod(intModulus.subtract(BigInteger.ONE));

    return Numbers.concatenateArrays(Numbers.i2osp(encryptedGenerator, keys.modulus.length), Numbers.i2osp(encryptedMessage, keys.modulus.length));
  }

  public static byte[] verify(byte[] digest, ElGamalKeys keys, byte[] signature) {
    BigInteger intModulus = new BigInteger(keys.modulus);
    BigInteger intPublic = new BigInteger(keys.personalPublicKey);
    BigInteger encryptedGenerator = new BigInteger(Arrays.copyOf(signature, keys.modulus.length));
    BigInteger encryptedMessage = new BigInteger(Arrays.copyOfRange(signature, keys.modulus.length, signature.length));

    BigInteger result = intPublic.modPow(encryptedGenerator, intModulus).multiply(encryptedGenerator.modPow(encryptedMessage, intModulus)).mod(intModulus);
    return Numbers.i2osp(result, keys.modulus.length);
  }
}
