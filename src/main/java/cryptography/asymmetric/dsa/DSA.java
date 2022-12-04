package cryptography.asymmetric.dsa;

import cryptography.asymmetric.Numbers;
import java.math.BigInteger;
import java.util.Arrays;

public class DSA {

  public static byte[] sign(byte[] digest, DSAKeys keys) {
    BigInteger intGroupOrder = new BigInteger(keys.groupOrder);
    BigInteger intModulus = new BigInteger(keys.modulus);
    BigInteger intGenerator = new BigInteger(keys.base);
    BigInteger intPrivate = new BigInteger(keys.personalPrivateKey);
    BigInteger randomValue;
    do {
      randomValue = new BigInteger(intGroupOrder.bitLength(), Numbers.random);
    } while (randomValue.compareTo(intGroupOrder) >= 0);
    BigInteger encryptedGenerator = intGenerator.modPow(randomValue, intModulus).mod(intGroupOrder);
    BigInteger intDigest = new BigInteger(digest);
    BigInteger inverseRandom = randomValue.modInverse(intGroupOrder);
    BigInteger encryptedMessage = inverseRandom.multiply(
        intDigest.add(intPrivate.multiply(encryptedGenerator))).mod(intGroupOrder);
    return Numbers.concatenateArrays(Numbers.i2osp(encryptedGenerator, keys.groupOrder.length),
        Numbers.i2osp(encryptedMessage, keys.groupOrder.length));
  }

  public static byte[] verify(byte[] digest, DSAKeys keys, byte[] signature) {
    BigInteger intGroupOrder = new BigInteger(keys.groupOrder);
    BigInteger intModulus = new BigInteger(keys.modulus);
    BigInteger intGenerator = new BigInteger(keys.base);
    BigInteger intPublic = new BigInteger(keys.personalPublicKey);
    BigInteger encryptedGenerator = new BigInteger(
        Arrays.copyOf(signature, keys.groupOrder.length));
    BigInteger encryptedMessage = new BigInteger(
        Arrays.copyOfRange(signature, keys.groupOrder.length, signature.length));
    BigInteger inverseEncryptedMessage = encryptedMessage.modInverse(intGroupOrder);
    BigInteger intDigest = new BigInteger(digest);
    BigInteger power1 = intDigest.multiply(inverseEncryptedMessage).mod(intGroupOrder);
    BigInteger power2 = encryptedGenerator.multiply(inverseEncryptedMessage).mod(intGroupOrder);
    BigInteger result = (intGenerator.modPow(power1, intModulus)
        .multiply(intPublic.modPow(power2, intModulus))).mod(intModulus).mod(intGroupOrder);
    return Numbers.i2osp(result, keys.groupOrder.length);
  }
}
