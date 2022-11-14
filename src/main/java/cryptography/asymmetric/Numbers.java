package cryptography.asymmetric;

import cryptography.asymmetric.GUI.UserSelections;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.jcajce.provider.digest.SHA256;
import org.bouncycastle.math.Primes;

public class Numbers {

  public static SecureRandom random = new SecureRandom();

  /**
   * Генерация криптографически безопасного случайного числа с длиной, кратной длине байта
   * @param bits длина генерируемого случайного числа в битах
   * @return случайное число
   * @throws IllegalArgumentException длина в битах не кратна байту (8)
   */
  public static BigInteger genNumber(int bits) throws IllegalArgumentException {
    if (bits < 1) {
      throw new IllegalArgumentException("Bits length have to be multiple of 8(byte)");
    }
    BigInteger candidate = new BigInteger(bits, random);
    while (candidate.equals(BigInteger.ZERO)) {
      candidate = new BigInteger(bits, random);
    }
    return candidate;
  }

  /**
   * Проверка числа на простоту используя решето из первых простых чисел (вплоть до числа 211) и 64/128 раундов Миллера-Рабина
   * @see <a href="https://javadox.com/org.bouncycastle/bcprov-jdk15on/1.53/org/bouncycastle/math/Primes.html">Bouncy castle prime test docs</a>
   * @param number число для проверки на простоту
   * @return false - число составное, true - вероятно простое
   */
  public static boolean isPrime(BigInteger number) {
    if (Primes.hasAnySmallFactors(number)) {
      return false;
    }
    return Primes.isMRProbablePrime(number, random, number.bitLength() > 2048 ? 128 : 64);
  }

  public static byte[] concatArrays(byte[]... arrays) {
    int length = 0;
    for (byte[] bytes : arrays) {
      length += bytes.length;
    }
    byte[] result = new byte[length];
    int shift = 0;
    for (byte[] bytes : arrays) {
      System.arraycopy(bytes, 0, result, shift, bytes.length);
      shift += bytes.length;
    }
    return result;
  }

  public static byte[] xorArrays(byte[] array1, byte[] array2) {
    byte[] resultArray = new byte[Math.max(array1.length, array2.length)];
    int i = 0;
    for (byte b : array1) {
      resultArray[i] = (byte) (b ^ array2[i++]);
    }
    return resultArray;
  }

  public static byte[][] splitArray(byte[] array, int chunkSize) throws IllegalArgumentException {
    if (chunkSize < 1) {
      throw new IllegalArgumentException("Invalid chunk size");
    }

    //Выделение места для двойного массива
    byte[][] splittedArray = new byte[(array.length + chunkSize - 1) / chunkSize][];

    //Последний подмассив обрабатывается отдельно так как может быть меньшей длины чем остальные (из-за того что длина входного массива не кратка размеру частей)
    int tailSize = array.length % chunkSize;
    if (tailSize != 0) {
      splittedArray[splittedArray.length - 1] = new byte[tailSize];
      System.arraycopy(array, array.length - tailSize, splittedArray[splittedArray.length - 1], 0, tailSize);
    } else {
      splittedArray[splittedArray.length - 1] = new byte[chunkSize];
      System.arraycopy(array, array.length - chunkSize, splittedArray[splittedArray.length - 1], 0, chunkSize);
    }

    //Заполнение подмассивов
    for (int i = 0; i < splittedArray.length - 1; i++) {
      splittedArray[i] = new byte[chunkSize];
      System.arraycopy(array, i * chunkSize, splittedArray[i], 0, chunkSize);
    }
    return splittedArray;
  }

  public static byte[] convert2Dto1D(byte[][] array2d) {
    int size1d = 0;
    for (byte[] bytes : array2d) {
      size1d += bytes.length;
    }
    byte[] array1d = new byte[size1d];
    int shift = 0;
    for (byte[] bytes : array2d) {
      System.arraycopy(bytes, 0, array1d, shift, bytes.length);
      shift += bytes.length;
    }
    return array1d;
  }

  public static byte[] concatenateArrays(byte[] arr1, byte[] arr2) {
    byte[] arrTemp = new byte[arr1.length + arr2.length];
    System.arraycopy(arr1, 0, arrTemp, 0, arr1.length);
    System.arraycopy(arr2, 0, arrTemp, arr1.length, arr2.length);
    return arrTemp;
  }


  /**
   * Создается группа вычетов. Применяется в таких алгоритмах как DH, ElGamal и др. для создания простого числа с большим делителем функции эйлера от модуля
   * <p>Группа может иметь как порядок равный функции Эйлера, т.е. для простого числа p это p-1, так и иной порядок, равный функции эйлера (p-1) делённой на один из её делителей, например (p-1)/2</p>
   * @see <a href="https://crypto.stackexchange.com/questions/25980/about-primitive-roots-mod-n-in-diffie-hellman">Почему у p-1 (функции Эйлера простого числа) должен быть большой простой множитель</a>
   * @see <a href="https://ru.wikipedia.org/wiki/%D0%9F%D0%B5%D1%80%D0%B2%D0%BE%D0%BE%D0%B1%D1%80%D0%B0%D0%B7%D0%BD%D1%8B%D0%B9_%D0%BA%D0%BE%D1%80%D0%B5%D0%BD%D1%8C_(%D1%82%D0%B5%D0%BE%D1%80%D0%B8%D1%8F_%D1%87%D0%B8%D1%81%D0%B5%D0%BB)">Первообразный корень (генератор) и то как он проверяется</a>
   * @param orderBits Количество бит (сгенерированных) порядка цикличной группы, обозначающий общее количество возможных элементов, которые можно получить путем {@code g^(1,2,3,...,p-1) mod p}
   * @return "Modulus" - Модуль группы вычетов, "Generator" - основание, позволяющее по указанному модулю получить необходимый порядок группы order
   */
  public static Map<String, BigInteger> generateCyclicGroup(int orderBits) {
    Map<String, BigInteger> groupParams = new HashMap<>();
    BigInteger subGroup;
    do {
      subGroup = new BigInteger(orderBits, Numbers.random);
    } while (subGroup.bitLength() != orderBits || !subGroup.isProbablePrime(128));
    BigInteger multiplier, modulus;
    do {
      multiplier = new BigInteger(16, Numbers.random);
      modulus = subGroup.multiply(multiplier).add(BigInteger.ONE);
    } while (!modulus.isProbablePrime(128));
    groupParams.put("Generator", new BigInteger(16, Numbers.random).modPow(multiplier, modulus));
    groupParams.put("Modulus", modulus);
    System.out.println(groupParams.get("Generator").modPow(subGroup, modulus));
    return groupParams;
  }

  /**
   * Преобразование в {@code BigInteger} неотрицательное целочисленное число массива байт
   * @see #i2osp(BigInteger, int)
   * @param data массив байт
   * @return {@code BigInteger} неотрицательное целочисленное число
   */
  public static BigInteger os2ip(byte[] data){
    return new BigInteger(1, data);
  }

  /**
   * Преобразует {@code BigInteger} целочисленное число в массив байт с фиксированной длиной, 0х00 байты ставятся в начало (big endian)
   * <p>RFC8017 описывает реализацию и то, для чего применяется (в OAEP)</p>
   * @see <a href="https://stackoverflow.com/questions/8515691/getting-1-byte-extra-in-the-modulus-rsa-key-and-sometimes-for-exponents-also">Пример применения</a>
   * @param data число, которое будет преобразовываться в байтовое представление
   * @param length длина выходного массива байт
   * @return {@code byte[]} массив, представляющий собой целочисленное число
   */
  public static byte[] i2osp(BigInteger data, int length){
    byte[] out = new byte[length];
    byte[] dataArray = data.toByteArray();
    int signByte = dataArray[0] == 0 ? 1 : 0;
    System.arraycopy(dataArray, signByte, out, length - dataArray.length + signByte, dataArray.length - signByte);
    return out;
  }
}
