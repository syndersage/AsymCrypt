package cryptography.asymmetric;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.math.Primes;

public class Numbers {

  public static char[] HEX = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
      'a', 'b', 'c', 'd', 'e', 'f'};

  public static SecureRandom random = new SecureRandom();

  //Длина случайно генерируемого числа для операции создания простого числа с большим множителем функции эйлера от этого простого числа
  public static int randomValueSize = 15;

  /**
   * Генерация криптографически безопасного случайного числа с длиной, кратной длине байта
   *
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
   * Проверка числа на простоту используя решето из первых простых чисел (вплоть до числа 211) и
   * 64/128 раундов Миллера-Рабина
   *
   * @param number число для проверки на простоту
   * @return false - число составное, true - вероятно простое
   * @see <a
   * href="https://javadox.com/org.bouncycastle/bcprov-jdk15on/1.53/org/bouncycastle/math/Primes.html">Bouncy
   * castle prime test docs</a>
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
      System.arraycopy(array, array.length - tailSize, splittedArray[splittedArray.length - 1], 0,
          tailSize);
    } else {
      splittedArray[splittedArray.length - 1] = new byte[chunkSize];
      System.arraycopy(array, array.length - chunkSize, splittedArray[splittedArray.length - 1], 0,
          chunkSize);
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
   * Создается группа вычетов. Применяется в таких алгоритмах как DSA для создания простого числа с
   * большим делителем функции эйлера от модуля
   * <p>Группа может иметь как порядок равный функции Эйлера, т.е. для простого числа p это p-1, так
   * и иной порядок, равный функции эйлера (p-1) делённой на один из её делителей, например
   * (p-1)/2</p>
   *
   * @param modulusSize Длина модуля в битах
   * @param groupSize   Длина порядка (группы) модуля {@code modulusSize}, т.е. количество бит
   *                    (сгенерированных) порядка цикличной группы, обозначающий общее количество
   *                    возможных элементов, которые можно получить путем
   *                    {@code g^(1,2,3,...,p-1) mod p}
   * @return "Modulus" - Модуль группы вычетов, "Generator" - основание, позволяющее по указанному
   * модулю получить необходимый порядок группы order
   * @see <a
   * href="https://crypto.stackexchange.com/questions/25980/about-primitive-roots-mod-n-in-diffie-hellman">Почему
   * у p-1 (функции Эйлера простого числа) должен быть большой простой множитель</a>
   * @see <a
   * href="https://ru.wikipedia.org/wiki/%D0%9F%D0%B5%D1%80%D0%B2%D0%BE%D0%BE%D0%B1%D1%80%D0%B0%D0%B7%D0%BD%D1%8B%D0%B9_%D0%BA%D0%BE%D1%80%D0%B5%D0%BD%D1%8C_(%D1%82%D0%B5%D0%BE%D1%80%D0%B8%D1%8F_%D1%87%D0%B8%D1%81%D0%B5%D0%BB)">Первообразный
   * корень (генератор) и то как он проверяется</a>
   */
  public static Map<String, BigInteger> generateCyclicGroup(int modulusSize, int groupSize)
      throws IllegalArgumentException {
    if (modulusSize > 6144 | modulusSize < 8) {
      throw new IllegalArgumentException("Modulus size must be between 8 and 6144 bits");
    }
    if (groupSize > 4096 | groupSize < 4) {
      throw new IllegalArgumentException("Group order must be between 4 and 4096 bits");
    }
    Map<String, BigInteger> groupParams = new HashMap<>();
    BigInteger subGroup;
    do {
      subGroup = new BigInteger(groupSize, Numbers.random);
    } while (subGroup.bitLength() != groupSize || !subGroup.isProbablePrime(128));
    BigInteger multiplier, modulus;
    //В алгоритме дважды используется генерация маленьких случайных чисел: один раз для создания модуля, второй для основания (генератора)
    //Брать число, кратное байту (8) не рекомендуется, так как модуль в результате будет иметь первый байт 0х00 в начале (для обозначения знака)
    //Как результат выбранного числа кратного байту, модуль, имея длину равную p, на деле будет являться длины p-1
    //Выбранное таким образом число приведет к тому что шифруемые данные из p байт будут больше чем модуль, а соответственно не будут входить, в виде числа, в мультипликативную группу порядка p
    int appendSize = modulusSize - groupSize;
    do {
      multiplier = new BigInteger(appendSize, Numbers.random);
      modulus = subGroup.multiply(multiplier).add(BigInteger.ONE);
    } while (modulus.bitLength() != (groupSize + appendSize) || !modulus.isProbablePrime(128));
    BigInteger base = new BigInteger(appendSize, Numbers.random).modPow(multiplier, modulus);
    groupParams.put("Generator", base);
    groupParams.put("Modulus", modulus);
    groupParams.put("Order", subGroup);
    return groupParams;
  }

  /**
   * Создается группа вычетов. Применяется в таких алгоритмах как DH, ElGamal и др. для создания
   * большого числа с большим делителем функции Эйлера от модуля, при этом размер модуля не является
   * фиксированной длины
   *
   * @param groupSize Длина порядка (группы) модуля {@code modulusSize}, т.е. количество бит
   *                  (сгенерированных) порядка цикличной группы, обозначающий общее количество
   *                  возможных элементов, которые можно получить путем
   *                  {@code g^(1,2,3,...,p-1) mod p}
   * @return "Modulus" - Модуль группы вычетов, "Generator" - основание, позволяющее по указанному
   * модулю получить необходимый порядок группы order
   */
  public static Map<String, BigInteger> generateCyclicGroup(int groupSize)
      throws IllegalArgumentException {
    return generateCyclicGroup(randomValueSize + groupSize, groupSize);
  }

  /**
   * Преобразование в {@code BigInteger} неотрицательное целочисленное число массива байт
   *
   * @param data массив байт
   * @return {@code BigInteger} неотрицательное целочисленное число
   * @see #i2osp(BigInteger, int)
   */
  public static BigInteger os2ip(byte[] data) {
    return new BigInteger(1, data);
  }

  /**
   * Преобразует {@code BigInteger} целочисленное число в массив байт с фиксированной длиной, 0х00
   * байты ставятся в начало (big endian)
   * <p>RFC8017 описывает реализацию и то, для чего применяется (в OAEP)</p>
   *
   * @param data   число, которое будет преобразовываться в байтовое представление
   * @param length длина выходного массива байт
   * @return {@code byte[]} массив, представляющий собой целочисленное число
   * @see <a
   * href="https://stackoverflow.com/questions/8515691/getting-1-byte-extra-in-the-modulus-rsa-key-and-sometimes-for-exponents-also">Пример
   * применения</a>
   */
  public static byte[] i2osp(BigInteger data, int length) {
    byte[] out = new byte[length];
    byte[] dataArray = data.toByteArray();
    int signByte = dataArray[0] == 0 ? 1 : 0;
    System.arraycopy(dataArray, signByte, out, length - dataArray.length + signByte,
        dataArray.length - signByte);
    return out;
  }

  public static String bytesToHex(byte[] bytes) {
    char[] hexArr = new char[2 * bytes.length];
    for (int i = 0, j = 0; j < bytes.length; j++) {
      hexArr[i++] = HEX[(0xF0 & bytes[j]) >>> 4];
      hexArr[i++] = HEX[0x0F & bytes[j]];
    }
    return new String(hexArr);
  }
}
