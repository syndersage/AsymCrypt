package cryptography.asymmetric.elgamal;

import cryptography.asymmetric.gui.UserSelections;
import cryptography.asymmetric.Numbers;
import cryptography.asymmetric.rsa.OAEP;
import java.math.BigInteger;
import java.util.Arrays;

public class ElGamal {
  public static byte[] encrypt(byte[] data, ElGamalKeys keys, OAEP paddingParams) {
    BigInteger randomValue, tempModulus = new BigInteger(keys.modulus);
    do {
      randomValue = new BigInteger(tempModulus.bitLength(), Numbers.random);
    } while (randomValue.compareTo(tempModulus.subtract(BigInteger.TWO)) >= 0);
    BigInteger tempGenerator = new BigInteger(keys.base);
    byte[] encryptedGenerator = Numbers.i2osp(tempGenerator.modPow(randomValue, tempModulus),
        keys.byteKeyLength);
    BigInteger tempPublic = new BigInteger(keys.personalPublicKey);
    int chunkSize;
    switch (paddingParams.padding) {
      case "PKCS#1-OAEP" -> {
        int bytesForPadding = 2 * UserSelections.digest.getDigestLength() + 2;
        chunkSize = keys.byteKeyLength - bytesForPadding;
        if (chunkSize <= 0) {
          throw new IllegalArgumentException(" Key size for PKCS#1-OAEP must be at least: " + (bytesForPadding * 8 + 1) + " bits");
        }
      }
      case "None" -> chunkSize = keys.byteKeyLength - 1;
      default -> throw new IllegalArgumentException(" Invalid padding name: " + paddingParams.padding);
    }
    byte[][] splittedData = Numbers.splitArray(data, chunkSize);
    byte[][] encryptedMessageChunks = new byte[splittedData.length][];
    byte[] messageChunk;
    UserSelections.progress.setMaximum(encryptedMessageChunks.length);
    for (int i = 0; i < splittedData.length; i++) {
      if (UserSelections.calculationThread.isCancelled()) {
        return new byte[0];
      }
      UserSelections.progress.setValue(i);
      switch (paddingParams.padding) {
        case "PKCS#1-OAEP" -> messageChunk = OAEP.wrap(splittedData[i], paddingParams);
        case "None" -> messageChunk = splittedData[i];
        default -> throw new IllegalArgumentException("Invalid padding name");
      }
      encryptedMessageChunks[i] = Numbers.i2osp(Numbers.os2ip(messageChunk).multiply(tempPublic.modPow(randomValue, tempModulus)).mod(tempModulus),
          keys.byteKeyLength);
    }
    return Numbers.concatArrays(encryptedGenerator, Numbers.convert2Dto1D(encryptedMessageChunks));
  }

  public static byte[] decrypt(byte[] data, ElGamalKeys keys, OAEP paddingParams) {
    BigInteger tempModulus = new BigInteger(keys.modulus);
    BigInteger encryptedGenerator = Numbers.os2ip(Arrays.copyOf(data, keys.byteKeyLength));
    byte[][] splittedData = Numbers.splitArray(Arrays.copyOfRange(data, keys.byteKeyLength, data.length), keys.byteKeyLength);
    byte[][] decryptedData = new byte[splittedData.length][];
    BigInteger tempPrivate = new BigInteger(keys.personalPrivateKey);
    BigInteger paddedChunk;
    UserSelections.progress.setMaximum(decryptedData.length);
    for (int i = 0; i < decryptedData.length; i++) {
      if (UserSelections.calculationThread.isCancelled()) {
        return new byte[0];
      }
      UserSelections.progress.setValue(i);
      paddedChunk = Numbers.os2ip(splittedData[i]);
      decryptedData[i] = Numbers.i2osp(paddedChunk.multiply(encryptedGenerator.modPow(tempModulus.subtract(BigInteger.ONE).subtract(tempPrivate), tempModulus)).mod(tempModulus),
          keys.byteKeyLength);
      switch (paddingParams.padding) {
        case "PKCS#1-OAEP" -> decryptedData[i] = OAEP.unwrap(decryptedData[i], paddingParams);
        case "None" -> decryptedData[i] = Arrays.copyOfRange(decryptedData[i], 1, keys.byteKeyLength);
      }
    }
    return Numbers.convert2Dto1D(decryptedData);
  }
}
