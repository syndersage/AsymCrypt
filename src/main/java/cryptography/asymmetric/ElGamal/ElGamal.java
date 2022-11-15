package cryptography.asymmetric.ElGamal;

import cryptography.asymmetric.Numbers;
import java.math.BigInteger;
import java.util.Arrays;

public class ElGamal {
  public static byte[] encrypt(byte[] data, ElGamalKeys keys) {
    System.out.println(keys.modulus.length);
    BigInteger randomValue, tempModulus = new BigInteger(keys.modulus);
    do {
      randomValue = new BigInteger(tempModulus.bitLength(), Numbers.random);
    } while (randomValue.compareTo(tempModulus.subtract(BigInteger.TWO)) >= 0);
    BigInteger tempGenerator = new BigInteger(keys.base);
    byte[] encryptedGenerator = Numbers.i2osp(tempGenerator.modPow(randomValue, tempModulus),
        keys.modulus.length);
    BigInteger tempPublic = new BigInteger(keys.personalPublicKey);
    byte[][] splittedData = Numbers.splitArray(data, keys.modulus.length - 1);
    byte[][] encryptedMessageChunks = new byte[splittedData.length][];
    for (int i = 0; i < splittedData.length; i++) {
      System.out.println(i);
      encryptedMessageChunks[i] = Numbers.i2osp(new BigInteger(1, splittedData[i]).multiply(tempPublic.modPow(randomValue, tempModulus)).mod(tempModulus),
          keys.modulus.length);
    }
    //byte[] encryptedMessage = new BigInteger(1, data).multiply(tempPublic.pow(randomValue, tempModulus)).mod(tempModulus).toByteArray();
    return Numbers.concatArrays(encryptedGenerator, Numbers.convert2Dto1D(encryptedMessageChunks));
  }

  public static byte[] decrypt(byte[] data, ElGamalKeys keys) {
    BigInteger tempModulus = new BigInteger(keys.modulus);
    BigInteger encryptedGenerator = Numbers.os2ip(Arrays.copyOf(data, keys.modulus.length));
    byte[][] encryptedMessageChunks = Numbers.splitArray(Arrays.copyOfRange(data, keys.modulus.length, data.length), keys.modulus.length);
    byte[][] decryptedMessageChunks = new byte[encryptedMessageChunks.length][];
    BigInteger tempPrivate = new BigInteger(keys.personalPrivateKey);
    for (int i = 0; i < encryptedMessageChunks.length; i++) {
      decryptedMessageChunks[i] = Numbers.i2osp(new BigInteger(1, encryptedMessageChunks[i]).multiply(encryptedGenerator.modPow(tempModulus.subtract(BigInteger.ONE).subtract(tempPrivate), tempModulus)).mod(tempModulus), keys.modulus.length);
    }
    for (int i = 0; i < decryptedMessageChunks.length; i++) {
      decryptedMessageChunks[i] = Arrays.copyOfRange(decryptedMessageChunks[i], 1, decryptedMessageChunks[i].length);
    }
    return Numbers.convert2Dto1D(decryptedMessageChunks);
  }
}
