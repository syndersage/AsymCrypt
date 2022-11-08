package cryptography.asymmetric.RSA;

import cryptography.asymmetric.GUI.UserSelections;
import cryptography.asymmetric.Numbers;
import java.security.MessageDigest;

public class MGF1 {

  /**
   * Mask generation function в соответствии с PKCS#1 (MGF1) для создания маски в паддинге OAEP
   * <p>MGF позволяет принимать данные одной длины, а возвращать данные другой (произвольной) длины, указываемой в параметре функции</p>
   * @param seed увеличение случайности функции
   * @param maskLength выходная длина маски (в байтах)
   * @return маска ({@code byte[]} набор данных) указанной длины
   * @throws IllegalArgumentException некорректная длина маски
   */
  public static byte[] mask(byte[] seed, long maskLength) throws IllegalArgumentException {
    //Если длина маски больше 32 бит (т.к. счетчик представляется в формате 4-х байтового числа)
    if (maskLength > 4294967296L) {
      throw new IllegalArgumentException("Mask too long");
    }
    //Запрет на маску отрицательного размера
    if (maskLength < 1) {
      throw new IllegalArgumentException("Mask too small");
    }
    MessageDigest digest = UserSelections.digest;
    //Начальная маска - пустой массив байт
    byte[] mask = new byte[0];
    //Одна итерация позволяет создать маску длины хэша
    for (long i = 0; i <= Math.ceil((double) maskLength / digest.getDigestLength()) - 1; i++) {
      //Добавление для вычисления хэша счетчика в 4-байтовом формате
      digest.update(new byte[] {(byte) (i >>> 24), (byte) (i >>> 16), (byte) (i >>> 8), (byte) i});
      //Добавление seed для вычисления хэша
      digest.update(seed);
      byte[] hash = digest.digest();
      //Объединения маски с предыдущих итераций и хэша новой итерации
      mask = Numbers.concatArrays(mask, hash);
    }
    byte[] output = new byte[(int) maskLength];
    System.arraycopy(mask, 0, output, 0, output.length);
    return output;
  }
}