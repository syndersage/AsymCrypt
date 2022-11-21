package cryptography.asymmetric.sha;

import cryptography.asymmetric.Numbers;
import cryptography.asymmetric.gui.UserSelections;
import java.nio.ByteBuffer;
import java.util.Arrays;

public class SHA {

  int h0 = 0x67452301;
  int h1 = 0xEFCDAB89;
  int h2 = 0x98BADCFE;
  int h3 = 0x10325476;
  int h4 = 0xC3D2E1F0;

  public byte[] calculate(byte[] data) {
    data = Numbers.concatArrays(data, paddingBits(data.length), paddingLength(data.length));
    //Вычисление промежуточного дайджеста для каждых 512 бит (64 байт) входных данных
    UserSelections.progress.setValue(0);
    UserSelections.progress.setMaximum((int) ((long) data.length * 8 / 512));
    for (int i = 0; i < (long) data.length * 8 / 512; i++) {
      UserSelections.progress.setValue(i);
      if (UserSelections.calculationThread.isCancelled()) {
        return new byte[0];
      }
      hashBlock(Arrays.copyOfRange(data, i * 64, (i + 1) * 64));
    }
    //Вычисление результата дайджеста путем соединения 5 буферов
    byte[] digest = new byte[20];
    System.arraycopy(ByteBuffer.allocate(4).putInt(h0).array(), 0, digest,  0, 4);
    System.arraycopy(ByteBuffer.allocate(4).putInt(h1).array(), 0, digest,  4, 4);
    System.arraycopy(ByteBuffer.allocate(4).putInt(h2).array(), 0, digest,  8, 4);
    System.arraycopy(ByteBuffer.allocate(4).putInt(h3).array(), 0, digest, 12, 4);
    System.arraycopy(ByteBuffer.allocate(4).putInt(h4).array(), 0, digest, 16, 4);
    System.out.println(Numbers.bytesToHex(digest));
    return digest;
  }

  public byte[] paddingBits(int bytesDataLength) {
    int bytesAppend;
    //Длина данных по модулю одного блока (64 байта) (512 бит)
    bytesDataLength = bytesDataLength % 64;
    //56 байт = 448 бит - требуемая конечная длина после паддинга битами (8 байт выделяется для указания длины всего сообщения)
    if (bytesDataLength == 56) {
      //Если длина по модулю 64 равна 56 (448 бит), то необходимо добавить один целый блок в 512 бит
      bytesAppend = 64;
    } else if (bytesDataLength < 56) {
      //Если длина по модулю меньше 56, то необходимо добавить (56 - количество недостающих байт)
      bytesAppend = 56 - bytesDataLength;
    } else {
      //Если длина по модулю больше 56, то необходимо добавить (56 + (64 - длина по модулю))
      bytesAppend = 56 + (64 - bytesDataLength);
    }
    //Все биты кроме первого равны 0
    byte[] paddingBytes = new byte[bytesAppend];
    //Первый бит равен 1
    paddingBytes[0] = (byte) 0x80;
    return paddingBytes;
  }

  public void hashBlock(byte[] dataBlock) {
    //В алгоритме работа производится не с байтами, а с 4-байтными целочисленными значениями
    //При этом входные данные (dataBlock) воспринимается как low-order, т.е. первый (левый) байт наименее значащий (Little-endian)
    int[] words = toIntegerRightOrder(dataBlock);

    //"Слова" расширяются до 80 элементов
    int[] extendedWords = new int[80];
    System.arraycopy(words, 0, extendedWords, 0, words.length);
    for (int i = 16; i < extendedWords.length; i++) {
      extendedWords[i] = Integer.rotateLeft(extendedWords[i - 3] ^ extendedWords[i - 8] ^ extendedWords[i - 14] ^ extendedWords[i - 16], 1);
    }

    //Для проведения операций с блоком копируются текущие величины буферов, после чего с ними проводятся операции
    int a = h0;
    int b = h1;
    int c = h2;
    int d = h3;
    int e = h4;
    int temp;
    for (int i = 0; i < extendedWords.length; i++) {
      temp = Integer.rotateLeft(a, 5) + round(i, b, c, d) + e + extendedWords[i] + getK(i);
      e = d;
      d = c;
      c = Integer.rotateLeft(b, 30);
      b = a;
      a = temp;
    }

    //Вычисленные для данного блока буферы прибавляются к уже существующим
    h0 += a;
    h1 += b;
    h2 += c;
    h3 += d;
    h4 += e;
  }

  public static int round(int index, int b, int c, int d) {
    //Операции с элементами буферов, зависящие от номера перебираемого "слова"
    int result = 0;
    switch (index / 20) {
      case 0 -> result = (b & c) | ((~b) & d);
      case 1, 3 -> result = b ^ c ^ d;
      case 2 -> result = (b & c) | (b & d) | (c & d);
    }
    return result;
  }

  public static int getK(int index) {
    //Константы, зависящие от номера перебираемого "слова" в алгоритме (0-19 - первое, 20-39 - второе, 40-59 - третье, 60-79 - четвертое)
    int k = 0;
    switch (index / 20) {
      case 0 -> k = 0x5A827999;
      case 1 -> k = 0x6ED9EBA1;
      case 2 -> k = 0x8F1BBCDC;
      case 3 -> k = 0xCA62C1D6;
    }
    return k;
  }



  public byte[] paddingLength(int bytesDataLength) {
    //Вычисляется длина сообщения в виде 8-байтового значения
    int bitsDataLength = bytesDataLength * 8;
    return Numbers.concatenateArrays(new byte[4], ByteBuffer.allocate(4).putInt(bitsDataLength).array());
  }

  public int[] toIntegerRightOrder(byte[] dataBlock) {
    //Преобразование массива байтов в массив целочисленных (4-байтовых) значений с Big-endian порядком
    ByteBuffer buffer = ByteBuffer.allocate(4);
    int[] words = new int[16];
    for (int i = 0; i < 16; i++) {
      buffer.put(Arrays.copyOfRange(dataBlock, i * 4, (i + 1) * 4));
      buffer.flip();
      words[i] = buffer.getInt();
      buffer.flip();
    }
    return words;
  }
}
