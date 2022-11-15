package cryptography.asymmetric.RSA;

import cryptography.asymmetric.GUI.UserSelections;
import cryptography.asymmetric.Numbers;
import cryptography.asymmetric.Padding;
import java.security.MessageDigest;
import java.util.Arrays;

public class OAEP implements Padding {

  public String padding;

  public byte[] seed;

  public byte[] label;

  public int bytesKeyLength;

  /**
   * Паддинд по стандарту PKCS#1 v2.2 шифруемого алгоритмом RSA сообщения. <p>В RFC8017 требуется seed фиксированного размера (длины хэш алгоритма) - для этого берется хэш от seed произвольного размера при помощи того же алгоритма хэширования</p>
   * @see <a href="https://www.rfc-editor.org/rfc/rfc8017">Докумментация на PKCS</a>
   * @param message сообщение, которое планируется шифровать
   * @param params параметры паддинга: seed - добавление недетерминированности, bytesKeyLength - длина ключа (модуля) в RSA, label - дополнительный текст для проверки целостности
   * @return {@code byte[]} сообщение, в которое добавлен паддинг
   */
  public static byte[] wrap(byte[] message, OAEP params)
  throws IllegalArgumentException {
    int bytesKeyLength = params.bytesKeyLength;
    byte[] label = params.label;
    byte[] seed = params.seed;
    MessageDigest digest = UserSelections.digest;
    //Длина возвращаемого хэша с выбранным алгоритмом (в байтах)
    int bytesDigestLength = digest.getDigestLength();
    //Проверка на максимальную длину одного сообщения - если не проходит, сообщение нужно делить
    if (message.length > bytesKeyLength - 2 * bytesDigestLength - 2) {
      throw new IllegalArgumentException("Message size too big");
    }
    //Ограничение на длину вспомогательного текста - метки (используется для идентификации шифруемого сообщения)
    if (label.length > bytesDigestLength) {
      throw new IllegalArgumentException("Label size too big");
    }
    byte[] labelHash = digest.digest(label);
    //Вычисление количества добавляемых байтов с нулями и их заполнение
    int bytesPaddingLength = bytesKeyLength - message.length - 2 * bytesDigestLength - 2;
    byte[] paddingString = new byte[bytesPaddingLength];
    Arrays.fill(paddingString, (byte) 0);
    //Объединение хэша метки, добавляемых нулей и доп. байта со значением 0х01
    byte[] dataBlock = Numbers.concatArrays(labelHash, paddingString, new byte[] {(byte) 0x01},
        message);
    if (dataBlock.length != (bytesKeyLength - bytesDigestLength - 1)) {
      throw new IllegalArgumentException("Incorrect data block size");
    }
    //seed произвольного размера становится фиксированного размера с помощью хеша, который применяется для метки
    seed = digest.digest(seed);
    //Генерация маски для блока данных на основе seed
    byte[] dataBlockMask = MGF1.mask(seed, bytesKeyLength - bytesDigestLength - 1);
    //XOR маски и блока данных
    byte[] maskedDataBlock = Numbers.xorArrays(dataBlock, dataBlockMask);
    //Генерация маски для блока seed на основе maskedDataBlock
    byte[] seedMask = MGF1.mask(maskedDataBlock, bytesDigestLength);
    //XOR seed и маски seed
    byte[] maskedSeed = Numbers.xorArrays(seed, seedMask);
    //Возврат объединенных: проверочного байта 0х00, блока seed под маской и блока данных под маской
    return Numbers.concatArrays(new byte[] {(byte) 0x00}, maskedSeed, maskedDataBlock);
  }

  /**
   * Удаление паддинга расшифрованного алгоритмом RSA сообщения. По стандарту PKCS#1 v2.2
   * @see <a href="https://www.rfc-editor.org/rfc/rfc8017">Докумментация на PKCS</a>
   * @param paddedMessage расшифрованное сообщение
   * @param params паддинга: label - дополнительный текст для проверки целостности, bytesKeyLength - длина ключа (модуля) в RSA (знание seed при удалении паддинга не нужно)
   * @return {@code byte[]} сообщение, из которого удален паддинг
   * @throws IllegalArgumentException При некорректном удалении паддинга на стадии проверки
   */
  public static byte[] unwrap(byte[] paddedMessage, OAEP params)
      throws IllegalArgumentException {
    byte[] label = params.label;
    int bytesKeyLength = params.bytesKeyLength;
    MessageDigest digest = UserSelections.digest;
    //Длина возвращаемого хэша с выбранным алгоритмом (в байтах)
    int bytesDigestLength = digest.getDigestLength();
    byte[] labelHash = digest.digest(label);
    //Разделение единого сообщения на проверочный байт, блок seed под маской и блок данных под маской
    if (paddedMessage[0] != 0) {
      throw new IllegalArgumentException("Padding is invalid", new IllegalArgumentException("0x00 byte at beginning of padded message not found"));
    }
    byte[] maskedSeed = Arrays.copyOfRange(paddedMessage, 1, 1 + bytesDigestLength);
    byte[] maskedDataBlock = Arrays.copyOfRange(paddedMessage, 1 + bytesDigestLength, paddedMessage.length);
    //Получение seed маски
    byte[] seedMask = MGF1.mask(maskedDataBlock, bytesDigestLength);
    //Получение seed, использовавшегося при добавлении паддинга
    byte[] seed = Numbers.xorArrays(maskedSeed, seedMask);
    //Вычисление маски блока данных зная seed
    byte[] dataBlockMask = MGF1.mask(seed, bytesKeyLength - bytesDigestLength - 1);
    //Вычисление блока данных
    byte[] dataBlock = Numbers.xorArrays(maskedDataBlock, dataBlockMask);
    int i = 0;
    //Разделение единого, переданного блока данных на хэш метки (и сравнение с хэшем переданной метки), добавляемые байты паддинга, проверочный бит 0х01 и исходное сообщение
    try {
      if (!Arrays.equals(labelHash, Arrays.copyOf(dataBlock, bytesDigestLength))) {
        throw new IllegalArgumentException("Label digests does not equal");
      }
      dataBlock = Arrays.copyOfRange(dataBlock, bytesDigestLength, dataBlock.length);
      while (i < dataBlock.length) {
        if (dataBlock[i] != 0) {
          if (dataBlock[i++] != 1) {
            throw new IllegalArgumentException("Padding string and message does not separated with 0x01");
          } else {
            break;
          }
        }
        i++;
      }
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException("Padding is invalid", e);
    }
    //От блока данных берется только исходное сообщение и возвращается
    return Arrays.copyOfRange(dataBlock, i, dataBlock.length);
  }

  //OAEP экземпляр содержит параметры паддинга
  public OAEP(byte[] seed, int bytesKeyLength, byte[] label) {
    this.seed = seed;
    this.bytesKeyLength = bytesKeyLength;
    this.label = label;
    this.padding = "PKCS#1-OAEP";
  }

  public OAEP(byte[] seed, int bytesKeyLength) {
    this.seed = seed;
    this.bytesKeyLength = bytesKeyLength;
    this.label = "".getBytes();
    this.padding = "PKCS#1-OAEP";
  }

  public OAEP(int bytesKeyLength, byte[] label) {
    this.seed = "".getBytes();
    this.bytesKeyLength = bytesKeyLength;
    this.label = label;
    this.padding = "PKCS#1-OAEP";
  }

  public OAEP(int bytesKeyLength) {
    this.seed = "".getBytes();
    this.bytesKeyLength = bytesKeyLength;
    this.label = "".getBytes();
    this.padding = "PKCS#1-OAEP";
  }

  //Без параметров - без паддинга
  public OAEP() {
    this.padding = "None";
  }
//
//  public static byte[] wrap(byte[] message, byte[] seed, int keyLength) throws IllegalArgumentException {
//    return wrap(message, seed, keyLength, "".getBytes(Numbers.charset));
//  }
//
//  public static byte[] wrap(byte[] message, int keyLength, byte[] label) throws IllegalArgumentException {
//    return wrap(message, "".getBytes(Numbers.charset), keyLength, label);
//  }
//
//  public static byte[] wrap(byte[] message, int keyLength) throws IllegalArgumentException {
//    return wrap(message, "".getBytes(Numbers.charset), keyLength);
//  }
//
//  public static byte[] unwrap(byte[] paddedMessage, int keyLength) throws IllegalArgumentException {
//    return unwrap(paddedMessage, keyLength, new byte[0]);
//  }

}
