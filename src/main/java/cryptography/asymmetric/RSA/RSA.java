package cryptography.asymmetric.RSA;

import cryptography.asymmetric.Cipher;
import cryptography.asymmetric.Numbers;
import java.math.BigInteger;
import java.util.Arrays;

public class RSA implements Cipher {


  public static byte[] encrypt(byte[] data, RSAKeys keys, OAEP paddingParams) throws NullPointerException, IllegalArgumentException {
    //System.out.println(keys.modulus.length);
    if (keys.publicKey == null | keys.modulus == null) {
      throw new NullPointerException("Key pair is not specified");
    }
    BigInteger publicKey = Numbers.os2ip(keys.publicKey);
    BigInteger modulus = Numbers.os2ip(keys.modulus);
    int byteKeyLength = keys.modulus.length;
    //Данные делятся на блоки, если они не помещаются в один (деление происходит на основании максимально допустимого значения по требованию OAEP)
    int messageSize;
    if (paddingParams.padding.equals("None")) {
      messageSize = byteKeyLength - 1;
    } else if (paddingParams.padding.equals("PKCS#1-OAEP")) {
      messageSize = byteKeyLength - 2 * Numbers.digest.getDigestLength() - 2;
      //Паддинг занимает (2 * длина_хэша + 2) места от блока, таким образом размер исходных блоков проверяется что он больше данного значения
      if (messageSize <= 0) {
        throw new IllegalArgumentException("Key length for selected padding+hash too small: padding gets " + ((Numbers.digest.getDigestLength() * 8 * 2) + 2) + " bits");
      }
    } else {
      throw new NullPointerException("Invalid padding name");
    }
    byte[][] splittedData = Numbers.splitArray(data, messageSize);
    for (byte[] bytes : splittedData) {
      System.out.println(Arrays.toString(bytes));
//      System.out.println(bytes.length);
    }
    byte[][] encryptedData = new byte[splittedData.length][];
    BigInteger paddedChunk;
    for (int i = 0; i < encryptedData.length; i++) {
      if (paddingParams.padding.equals("PKCS#1-OAEP")) {
        //Каждому блоку добавляется паддинг (OAEP), результат преобразуется в положительный integer
        paddedChunk = Numbers.os2ip(OAEP.wrap(splittedData[i], paddingParams));
        //Производится шифрования и результат обратно преобразуется в массив байт
        encryptedData[i] = Numbers.i2osp(paddedChunk.modPow(publicKey, modulus), byteKeyLength);
      } else if (paddingParams.padding.equals("None")) {
        encryptedData[i] = Numbers.i2osp(new BigInteger(1, splittedData[i]).modPow(publicKey, modulus), byteKeyLength);
        System.out.println("ENCRYPTED: " + Arrays.toString(encryptedData[i]));
      }
    }
    //Блоки объединяются в один
    return Numbers.convert2Dto1D(encryptedData);
  }

  public static byte[] decrypt(byte[] data, RSAKeys keys, OAEP paddingParams) throws NullPointerException {
    if (keys.privateKey == null | keys.modulus == null) {
      throw new NullPointerException("Key pair is not specified");
    }
    BigInteger privateKey = Numbers.os2ip(keys.privateKey);
    BigInteger modulus = Numbers.os2ip(keys.modulus);
    int byteKeyLength = keys.modulus.length;
    byte[][] splittedData = Numbers.splitArray(data, byteKeyLength);
    for (byte[] bytes : splittedData) {
      System.out.println("RECEIVED: " + Arrays.toString(bytes));
    }
    byte[][] decryptedData = new byte[splittedData.length][];
    BigInteger paddedChunk;
    for (int i = 0; i < decryptedData.length; i++) {
      if (paddingParams.padding.equals("PKCS#1-OAEP")) {
        if (byteKeyLength - 2 * Numbers.digest.getDigestLength() - 2 <= 0) {
          throw new IllegalArgumentException("Key length for selected padding+hash too small: padding gets " + ((Numbers.digest.getDigestLength() * 8 * 2) + 2) + " bits");
        }
        paddedChunk = Numbers.os2ip(splittedData[i]);
        decryptedData[i] = Numbers.i2osp(paddedChunk.modPow(privateKey, modulus), byteKeyLength);
        decryptedData[i] = OAEP.unwrap(decryptedData[i], paddingParams);
      } else if (paddingParams.padding.equals("None")) {
        System.out.println("WTF");
        decryptedData[i] = Numbers.i2osp(new BigInteger(1, splittedData[i]).modPow(privateKey, modulus), byteKeyLength);
        //Так как шифруемый блок размером (длина ключа в байтах - 1), то первый байт после операции сверху всегда будет ноль, а общий размер равен длине ключа в байтах
        //Это вызвано проблемой деления на блоки: если блоки будут длины ключа, то их целочисленное выражение может быть больше модуля, поэтому берется на 1 байт меньше
        byte[] removeFirstByte = new byte[byteKeyLength - 1];
        System.arraycopy(decryptedData[i], 1, removeFirstByte, 0, byteKeyLength - 1);
        decryptedData[i] = removeFirstByte;
      } else {
        throw new NullPointerException("Invalid padding name");
      }
    }
    for (byte[] bytes : decryptedData) {
      System.out.println("DECRYPTED: " + Arrays.toString(bytes));
    }
    return Numbers.convert2Dto1D(decryptedData);
  }
}
