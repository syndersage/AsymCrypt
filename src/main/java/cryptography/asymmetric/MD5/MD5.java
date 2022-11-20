package cryptography.asymmetric.MD5;

import cryptography.asymmetric.Numbers;
import java.nio.ByteBuffer;
import java.util.Arrays;

public class MD5 {

  int[] states = new int[] {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};

  private final static int[] h0 = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};
  private int[] h = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};

  final int[] T = { 0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
                    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
                    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
                    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
                    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
                    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
                    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
                    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
                    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
                    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
                    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
                    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
                    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
                    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
                    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
                    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

  final int[][] shift = { {7, 12, 17, 22},
                          {5, 9, 14, 20},
                          {4, 11, 16, 23},
                          {6, 10, 15, 21}};

  public byte[] calculate(byte[] data) {
    System.out.println(Arrays.toString(data));
    //К данным добавляются 0-е биты (кроме первого - он 1), так, чтобы длина стала 448 бит по модулю 512 (если длина до паддинга уже 448, то все равно добавляется 1 блок (512 бит))
    //Затем добавляется длина входных данных в битах в виде 64-битного числа
    data = Numbers.concatArrays(data, paddingBits(data.length), paddingLength(data.length));
    for (int i = 0; i < data.length * 8 / 512; i++) {
      System.out.println(Arrays.toString(byteArrToIntArr(data)));
      hashBlock(byteArrToIntArr(data));
      //hashBlock(Arrays.copyOfRange(data, i * 64, (i + 1) * 64));
    }
    byte[] byteArray = new byte[16];
    for (int k=0; k<4; k++) {
      toBytesBigEndian(h[k], byteArray, k*4);
    }
    System.out.println(bytesToHex(byteArray));
    return null;
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
    int bitDataLength = byteDataLength * 8;
    bitDataLength = Integer.reverseBytes(bitDataLength);
    byte[] dataLengthByteArray = ByteBuffer.allocate(4).putInt(bitDataLength).array();
    //Так как на вход сразу передаются все данные, а не последовательно читаемый поток, то максимальная длина равна Integer.MAX, т.е. 32-битному значению, остальные 32 бита это нули
    return Numbers.concatenateArrays(dataLengthByteArray, new byte[4]);
  }

//  public void hashBlock(byte[] dataBlock) {
//    int[] words = toIntegerLowOrder(dataBlock);
//
//    int[] buff = Arrays.copyOf(states, 4);
//
//    int round = 1;
//    for (int i = 0; i < 16; i++) {
//      buff[0] = buff[1] + (Numbers.rotateIntLeft(buff[0] + round1(buff[1], buff[2], buff[3]) + words[i] + T[i], shift[round - 1][i % 4]));
//      rotateBuff(buff);
//    }
//
//    round = 2;
//    for (int i = 0; i < 16; i++) {
//      buff[0] = buff[1] + (Numbers.rotateIntLeft(buff[0] + round2(buff[1], buff[2], buff[3]) + words[i] + T[16 + i], shift[round - 1][i % 4]));
//      rotateBuff(buff);
//    }
//
//    round = 3;
//    for (int i = 0; i < 16; i++) {
//      buff[0] = buff[1] + (Numbers.rotateIntLeft(buff[0] + round3(buff[1], buff[2], buff[3]) + words[i] + T[32 + i], shift[round - 1][i % 4]));
//      rotateBuff(buff);
//    }
//
//    round = 4;
//    for (int i = 0; i < 16; i++) {
//      buff[0] = buff[1] + (Numbers.rotateIntLeft(buff[0] + round4(buff[1], buff[2], buff[3]) + words[i] + T[48 + i], shift[round - 1][i % 4]));
//      rotateBuff(buff);
//    }
//
//    for (int i = 0; i < buff.length; i++) {
//      states[i] += buff[i];
//    }
//  }

  public void hashBlock(int[] block) {
    int a = h[0];
    int b = h[1];
    int c = h[2];
    int d = h[3];

    //System.out.println(Bits.toHexString(block));

    // flip the endian-ness of the input block
    int[] x = revBytes(block);

    // Round 1
    a = ff(a, b, c, d, x[ 0],  7, 0xd76aa478); /* 1 */
    d = ff(d, a, b, c, x[ 1], 12, 0xe8c7b756); /* 2 */
    c = ff(c, d, a, b, x[ 2], 17, 0x242070db); /* 3 */
    b = ff(b, c, d, a, x[ 3], 22, 0xc1bdceee); /* 4 */
    a = ff(a, b, c, d, x[ 4],  7, 0xf57c0faf); /* 5 */
    d = ff(d, a, b, c, x[ 5], 12, 0x4787c62a); /* 6 */
    c = ff(c, d, a, b, x[ 6], 17, 0xa8304613); /* 7 */
    b = ff(b, c, d, a, x[ 7], 22, 0xfd469501); /* 8 */
    a = ff(a, b, c, d, x[ 8],  7, 0x698098d8); /* 9 */
    d = ff(d, a, b, c, x[ 9], 12, 0x8b44f7af); /* 10 */
    c = ff(c, d, a, b, x[10], 17, 0xffff5bb1); /* 11 */
    b = ff(b, c, d, a, x[11], 22, 0x895cd7be); /* 12 */
    a = ff(a, b, c, d, x[12],  7, 0x6b901122); /* 13 */
    d = ff(d, a, b, c, x[13], 12, 0xfd987193); /* 14 */
    c = ff(c, d, a, b, x[14], 17, 0xa679438e); /* 15 */
    b = ff(b, c, d, a, x[15], 22, 0x49b40821); /* 16 */

    // Round 2
    a = gg(a, b, c, d, x[ 1],  5, 0xf61e2562); /* 17 */
    d = gg(d, a, b, c, x[ 6],  9, 0xc040b340); /* 18 */
    c = gg(c, d, a, b, x[11], 14, 0x265e5a51); /* 19 */
    b = gg(b, c, d, a, x[ 0], 20, 0xe9b6c7aa); /* 20 */
    a = gg(a, b, c, d, x[ 5],  5, 0xd62f105d); /* 21 */
    d = gg(d, a, b, c, x[10],  9,  0x2441453); /* 22 */
    c = gg(c, d, a, b, x[15], 14, 0xd8a1e681); /* 23 */
    b = gg(b, c, d, a, x[ 4], 20, 0xe7d3fbc8); /* 24 */
    a = gg(a, b, c, d, x[ 9],  5, 0x21e1cde6); /* 25 */
    d = gg(d, a, b, c, x[14],  9, 0xc33707d6); /* 26 */
    c = gg(c, d, a, b, x[ 3], 14, 0xf4d50d87); /* 27 */
    b = gg(b, c, d, a, x[ 8], 20, 0x455a14ed); /* 28 */
    a = gg(a, b, c, d, x[13],  5, 0xa9e3e905); /* 29 */
    d = gg(d, a, b, c, x[ 2],  9, 0xfcefa3f8); /* 30 */
    c = gg(c, d, a, b, x[ 7], 14, 0x676f02d9); /* 31 */
    b = gg(b, c, d, a, x[12], 20, 0x8d2a4c8a); /* 32 */

    // Round 3
    a = hh(a, b, c, d, x[ 5],  4, 0xfffa3942); /* 33 */
    d = hh(d, a, b, c, x[ 8], 11, 0x8771f681); /* 34 */
    c = hh(c, d, a, b, x[11], 16, 0x6d9d6122); /* 35 */
    b = hh(b, c, d, a, x[14], 23, 0xfde5380c); /* 36 */
    a = hh(a, b, c, d, x[ 1],  4, 0xa4beea44); /* 37 */
    d = hh(d, a, b, c, x[ 4], 11, 0x4bdecfa9); /* 38 */
    c = hh(c, d, a, b, x[ 7], 16, 0xf6bb4b60); /* 39 */
    b = hh(b, c, d, a, x[10], 23, 0xbebfbc70); /* 40 */
    a = hh(a, b, c, d, x[13],  4, 0x289b7ec6); /* 41 */
    d = hh(d, a, b, c, x[ 0], 11, 0xeaa127fa); /* 42 */
    c = hh(c, d, a, b, x[ 3], 16, 0xd4ef3085); /* 43 */
    b = hh(b, c, d, a, x[ 6], 23,  0x4881d05); /* 44 */
    a = hh(a, b, c, d, x[ 9],  4, 0xd9d4d039); /* 45 */
    d = hh(d, a, b, c, x[12], 11, 0xe6db99e5); /* 46 */
    c = hh(c, d, a, b, x[15], 16, 0x1fa27cf8); /* 47 */
    b = hh(b, c, d, a, x[ 2], 23, 0xc4ac5665); /* 48 */

    // Round 4
    a = ii(a, b, c, d, x[ 0],  6, 0xf4292244); /* 49 */
    d = ii(d, a, b, c, x[ 7], 10, 0x432aff97); /* 50 */
    c = ii(c, d, a, b, x[14], 15, 0xab9423a7); /* 51 */
    b = ii(b, c, d, a, x[ 5], 21, 0xfc93a039); /* 52 */
    a = ii(a, b, c, d, x[12],  6, 0x655b59c3); /* 53 */
    d = ii(d, a, b, c, x[ 3], 10, 0x8f0ccc92); /* 54 */
    c = ii(c, d, a, b, x[10], 15, 0xffeff47d); /* 55 */
    b = ii(b, c, d, a, x[ 1], 21, 0x85845dd1); /* 56 */
    a = ii(a, b, c, d, x[ 8],  6, 0x6fa87e4f); /* 57 */
    d = ii(d, a, b, c, x[15], 10, 0xfe2ce6e0); /* 58 */
    c = ii(c, d, a, b, x[ 6], 15, 0xa3014314); /* 59 */
    b = ii(b, c, d, a, x[13], 21, 0x4e0811a1); /* 60 */
    a = ii(a, b, c, d, x[ 4],  6, 0xf7537e82); /* 61 */
    d = ii(d, a, b, c, x[11], 10, 0xbd3af235); /* 62 */
    c = ii(c, d, a, b, x[ 2], 15, 0x2ad7d2bb); /* 63 */
    b = ii(b, c, d, a, x[ 9], 21, 0xeb86d391); /* 64 */

    // zero out inputs
    Arrays.fill(x, 0);

    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
  }

  private int f(int x, int y, int z) {
    return (x & y) | ((~x) & z);
  }

  private int g(int x, int y, int z) {
    return (x & z) | (y & (~z));
  }

  private int h(int x, int y, int z) {
    return (x ^ y ^ z);
  }

  private int i(int x, int y, int z) {
    return (y ^ (x | (~z)));
  }

  private int ff(int a, int b, int c, int d, int x, int s, int ac)
  {
    return leftRotate(a + f(b, c, d) + x + ac, s) + b;
  }

  private int gg(int a, int b, int c, int d, int x, int s, int ac)
  {
    return leftRotate(a + g(b, c, d) + x + ac, s) + b;
  }

  private int hh(int a, int b, int c, int d, int x, int s, int ac)
  {
    return leftRotate(a + h(b, c, d) + x + ac, s) + b;
  }

  private int ii(int a, int b, int c, int d, int x, int s, int ac)
  {
    return leftRotate(a + i(b, c, d) + x + ac, s) + b;
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

  public int round1(int in1, int in2, int in3) {
    return (in1 & in2) | (~in1 & in3);
  }

  public int round2(int in1, int in2, int in3) {
    return (in1 & in3) | (in2 & ~in3);
  }

  public int round3(int in1, int in2, int in3) {
    return in1 ^ in2 ^ in3;
  }

  public int round4(int in1, int in2, int in3) {
    return in2 ^ (in1 | ~in3);
  }

  public void rotateBuff(int[] buff) {
    int temp = buff[3];
    buff[3] = buff[2];
    buff[2] = buff[1];
    buff[1] = buff[0];
    buff[0] = temp;
  }

  public String bytesToHex(byte[] bytes) {
    char[] hexArr = new char[2 * bytes.length];
    for (int i = 0, j = 0; j < bytes.length; j++) {
      hexArr[i++] = Numbers.HEX[(0xF0 & bytes[j]) >>> 4];
      hexArr[i++] = Numbers.HEX[0x0F & bytes[j]];
    }
    return new String(hexArr);
  }

  public int revBytes(int x) {
    return (x >>> 24) | ((x >>> 8) & 0x0000FF00) | ((x << 8) & 0x00FF0000) | (x << 24);
  }

  public int[] revBytes(int[] block) {
    int[] result = new int[16];
    for (int i = 0; i < result.length; i++) {
      result[i] = revBytes(block[i]);
    }
    return result;
  }

  public int leftRotate(int a, int shift) {
    shift %= 32;
    return (a << shift) | (a >>> (32 - shift));
  }

  public int[] byteArrToIntArr(byte[] bytes) {
    int[] result = new int[16];
    int i = 0;
    for (int k = 0; k < 16; k++) {
      result[k] = toInt(bytes, i);
      i += 4;
    }
    return result;
  }

  public static int toInt(byte[] b, int offset) {
    return ((b[offset] & 0xFF) << 24)
        | ((b[offset+1] & 0xFF) << 16)
        | ((b[offset+2] & 0xFF) << 8)
        | (b[offset+3] & 0xFF);
  }

  public static void toBytesBigEndian(int a, byte[] bytes, int offset) {
    bytes[offset+3]   = (byte)((a >>> 24) & 0x000000FF);
    bytes[offset+2] = (byte)((a >>> 16) & 0x000000FF);
    bytes[offset+1] = (byte)((a >>> 8) & 0x000000FF);
    bytes[offset] = (byte)((a) & 0x000000FF);
  }
}
