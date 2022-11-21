package cryptography.asymmetric.md5;

import cryptography.asymmetric.Numbers;
import cryptography.asymmetric.gui.UserSelections;
import java.nio.ByteBuffer;
import java.util.Arrays;

public class MD5 {

  int[] states = new int[] {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};

  public byte[] calculate(byte[] data) {
    //К данным добавляются 0-е биты (кроме первого - он 1), так, чтобы длина стала 448 бит по модулю 512 (если длина до паддинга уже 448, то все равно добавляется 1 блок (512 бит))
    //Затем добавляется длина входных данных в битах в виде 64-битного числа
    data = Numbers.concatArrays(data, paddingBits(data.length), paddingLength(data.length));
    UserSelections.progress.setValue(0);
    UserSelections.progress.setMaximum((int) ((long) data.length * 8 / 512));
    for (int i = 0; i < (long) data.length * 8 / 512; i++) {
      if (UserSelections.calculationThread.isCancelled()) {
        return new byte[0];
      }
      UserSelections.progress.setValue(i);
      hashBlock(Arrays.copyOfRange(data, i * 64, (i + 1) * 64));
    }
    byte[] byteArray = new byte[16];
    for (int k=0; k<4; k++) {
      toBytesBigEndian(states[k], byteArray, k*4);
    }
    return byteArray;
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

  public byte[] paddingLength(int byteDataLength) {
    long bitDataLength = byteDataLength * 8L;
    bitDataLength = Long.reverseBytes(bitDataLength);
    //Так как на вход сразу передаются все данные, а не последовательно читаемый поток, то максимальная длина равна Integer.MAX, т.е. 32-битному значению, остальные 32 бита это нули
    return ByteBuffer.allocate(8).putLong(bitDataLength).array();
  }

  public void hashBlock(byte[] dataBlock) {
    //В алгоритме работа производится не с байтами, а с 4-байтными целочисленными значениями
    //При этом входные данные (dataBlock) воспринимается как low-order, т.е. первый (левый) байт наименее значащий (Little-endian)
    int[] words = toIntegerLowOrder(dataBlock);

    //Записываются состояния 4 буферов
    int a = states[0];
    int b = states[1];
    int c = states[2];
    int d = states[3];

    //Цикл 1
    //Общий принцип установки параметров на каждом цикле:
    //a, b, c, d - буферы, words[i] - конвертированные в int четыре байта блока, s - сдвиг, t - константа, создаваемая на основе синуса и порядкового номера итерации (0 - 63)
    a = round1(a, b, c, d, words[0],  7, 0xd76aa478);
    d = round1(d, a, b, c, words[1], 12, 0xe8c7b756);
    c = round1(c, d, a, b, words[2], 17, 0x242070db);
    b = round1(b, c, d, a, words[ 3],22, 0xc1bdceee);
    a = round1(a, b, c, d, words[ 4], 7, 0xf57c0faf);
    d = round1(d, a, b, c, words[ 5],12, 0x4787c62a);
    c = round1(c, d, a, b, words[ 6],17, 0xa8304613);
    b = round1(b, c, d, a, words[ 7],22, 0xfd469501);
    a = round1(a, b, c, d, words[ 8], 7, 0x698098d8);
    d = round1(d, a, b, c, words[ 9],12, 0x8b44f7af);
    c = round1(c, d, a, b, words[10],17, 0xffff5bb1);
    b = round1(b, c, d, a, words[11],22, 0x895cd7be);
    a = round1(a, b, c, d, words[12], 7, 0x6b901122);
    d = round1(d, a, b, c, words[13],12, 0xfd987193);
    c = round1(c, d, a, b, words[14],17, 0xa679438e);
    b = round1(b, c, d, a, words[15],22, 0x49b40821);

    //Цикл 2
    a = round2(a, b, c, d, words[ 1],  5, 0xf61e2562);
    d = round2(d, a, b, c, words[ 6],  9, 0xc040b340);
    c = round2(c, d, a, b, words[11], 14, 0x265e5a51);
    b = round2(b, c, d, a, words[ 0], 20, 0xe9b6c7aa);
    a = round2(a, b, c, d, words[ 5],  5, 0xd62f105d);
    d = round2(d, a, b, c, words[10],  9,  0x2441453);
    c = round2(c, d, a, b, words[15], 14, 0xd8a1e681);
    b = round2(b, c, d, a, words[ 4], 20, 0xe7d3fbc8);
    a = round2(a, b, c, d, words[ 9],  5, 0x21e1cde6);
    d = round2(d, a, b, c, words[14],  9, 0xc33707d6);
    c = round2(c, d, a, b, words[ 3], 14, 0xf4d50d87);
    b = round2(b, c, d, a, words[ 8], 20, 0x455a14ed);
    a = round2(a, b, c, d, words[13],  5, 0xa9e3e905);
    d = round2(d, a, b, c, words[ 2],  9, 0xfcefa3f8);
    c = round2(c, d, a, b, words[ 7], 14, 0x676f02d9);
    b = round2(b, c, d, a, words[12], 20, 0x8d2a4c8a);

    //Цикл 3
    a = round3(a, b, c, d, words[ 5],  4, 0xfffa3942);
    d = round3(d, a, b, c, words[ 8], 11, 0x8771f681);
    c = round3(c, d, a, b, words[11], 16, 0x6d9d6122);
    b = round3(b, c, d, a, words[14], 23, 0xfde5380c);
    a = round3(a, b, c, d, words[ 1],  4, 0xa4beea44);
    d = round3(d, a, b, c, words[ 4], 11, 0x4bdecfa9);
    c = round3(c, d, a, b, words[ 7], 16, 0xf6bb4b60);
    b = round3(b, c, d, a, words[10], 23, 0xbebfbc70);
    a = round3(a, b, c, d, words[13],  4, 0x289b7ec6);
    d = round3(d, a, b, c, words[ 0], 11, 0xeaa127fa);
    c = round3(c, d, a, b, words[ 3], 16, 0xd4ef3085);
    b = round3(b, c, d, a, words[ 6], 23,  0x4881d05);
    a = round3(a, b, c, d, words[ 9],  4, 0xd9d4d039);
    d = round3(d, a, b, c, words[12], 11, 0xe6db99e5);
    c = round3(c, d, a, b, words[15], 16, 0x1fa27cf8);
    b = round3(b, c, d, a, words[ 2], 23, 0xc4ac5665);

    //Цикл 4
    a = round4(a, b, c, d, words[ 0],  6, 0xf4292244);
    d = round4(d, a, b, c, words[ 7], 10, 0x432aff97);
    c = round4(c, d, a, b, words[14], 15, 0xab9423a7);
    b = round4(b, c, d, a, words[ 5], 21, 0xfc93a039);
    a = round4(a, b, c, d, words[12],  6, 0x655b59c3);
    d = round4(d, a, b, c, words[ 3], 10, 0x8f0ccc92);
    c = round4(c, d, a, b, words[10], 15, 0xffeff47d);
    b = round4(b, c, d, a, words[ 1], 21, 0x85845dd1);
    a = round4(a, b, c, d, words[ 8],  6, 0x6fa87e4f);
    d = round4(d, a, b, c, words[15], 10, 0xfe2ce6e0);
    c = round4(c, d, a, b, words[ 6], 15, 0xa3014314);
    b = round4(b, c, d, a, words[13], 21, 0x4e0811a1);
    a = round4(a, b, c, d, words[ 4],  6, 0xf7537e82);
    d = round4(d, a, b, c, words[11], 10, 0xbd3af235);
    c = round4(c, d, a, b, words[ 2], 15, 0x2ad7d2bb);
    b = round4(b, c, d, a, words[ 9], 21, 0xeb86d391);

    //Буферы преобразуются в новое значения по результату очередного блока
    states[0] += a;
    states[1] += b;
    states[2] += c;
    states[3] += d;
  }

  public int[] toIntegerLowOrder(byte[] dataBlock) {
    ByteBuffer buffer = ByteBuffer.allocate(4);
    int[] words = new int[16];
    for (int i = 0; i < 16; i++) {
      buffer.put(Arrays.copyOfRange(dataBlock, i * 4, (i + 1) * 4));
      buffer.flip();
      words[i] = Integer.reverseBytes(buffer.getInt());
      buffer.flip();
    }
    return words;
  }

  public int round1(int a, int b, int c, int d, int x, int s, int t) {
    return b + (leftRotate(a + ((b & c) | (~b & d)) + x + t, s));
  }

  public int round2(int a, int b, int c, int d, int x, int s, int t) {
    return b + (leftRotate(a + ((b & d) | (c & ~d)) + x + t, s));
  }
  
  public int round3(int a, int b, int c, int d, int x, int s, int t) {
    return b + (leftRotate(a + (b ^ c ^ d) + x + t, s));
  }  
  
  public int round4(int a, int b, int c, int d, int x, int s, int t) {
    return b + (leftRotate(a + (c ^ (b | ~d)) + x + t, s));
  }

  public int leftRotate(int a, int shift) {
    shift %= 32;
    return (a << shift) | (a >>> (32 - shift));
  }

  public static void toBytesBigEndian(int a, byte[] bytes, int offset) {
    bytes[offset+3]   = (byte)((a >>> 24) & 0x000000FF);
    bytes[offset+2] = (byte)((a >>> 16) & 0x000000FF);
    bytes[offset+1] = (byte)((a >>> 8) & 0x000000FF);
    bytes[offset] = (byte)((a) & 0x000000FF);
  }
}
