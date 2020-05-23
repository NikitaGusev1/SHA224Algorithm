
package sha224;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;

public class Sha224
{
    private static final int[] K = { 0x428a2f98, 0x71374491, 0xb5c0fbcf,
            0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74,
            0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
            0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc,
            0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85,
            0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb,
            0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70,
            0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3,
            0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f,
            0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2 };

    private static final int[] H0 = { 0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939, 0xFFC00B31, 0x68581511, 0x64F98FA7, 0xBEFA4FA4 };

    private static final int[] W = new int[64];
    private static final int[] H = new int[8];
    private static final int[] TEMP = new int[8];
/**
     * Hešavimas SHA-224 algoritmu
     *
     * @param message baitai, paduoti hešavimui
     * @return hešuoti baitai
     */
    public static byte[] hash(byte[] message)
    {
        // H = H0
        System.arraycopy(H0, 0, H, 0, H0.length);

        // inicializuojam žodžių masyvą
        int[] words = toIntArray(pad(message));

        // sudarom blokus (1 blokas - 16 žodžių)
        for (int i = 0, n = words.length / 16; i < n; ++i) {

            // inicializuojam masyvą W iš bloko žodžių
            System.arraycopy(words, i * 16, W, 0, 16);
            for (int t = 16; t < W.length; ++t) {
                W[t] = smallSig1(W[t - 2]) + W[t - 7] + smallSig0(W[t - 15])
                        + W[t - 16];
            }

            // TEMP = H
            System.arraycopy(H, 0, TEMP, 0, H.length);

            // atliekam operacijas su TEMP
            for (int t = 0; t < W.length; ++t) {
                int t1 = TEMP[7] + bigSig1(TEMP[4])
                        + ch(TEMP[4], TEMP[5], TEMP[6]) + K[t] + W[t];
                int t2 = bigSig0(TEMP[0]) + maj(TEMP[0], TEMP[1], TEMP[2]);
                System.arraycopy(TEMP, 0, TEMP, 1, TEMP.length - 1);
                TEMP[4] += t1;
                TEMP[0] = t1 + t2;
            }

            // sudedam TEMP ir H reikšmes
            for (int t = 0; t < H.length; ++t) {
                H[t] += TEMP[t];
            }

        }

        return toByteArray(H);
    }
    /**
     * Padidiname žinutę taip, kad ji taptų
     * 512 bitų kartotiniu, įskaitant 1-bit ir 0-bit k kartų pridėjimą.
     * Be to, paduotos reikšmės ilgis tampa toks, kaip 64 bitų skaičiaus.
     *
     * @param message paduota hešavimui reikšmė.
     * @return masyvas su pakeista reikšme.
     */
    public static byte[] pad(byte[] message)
    {
        final int blockBits = 512;
        final int blockBytes = blockBits / 8;

        // naujas žinutės ilgis
        int newMessageLength = message.length + 1 + 8;
        int padBytes = blockBytes - (newMessageLength % blockBytes);
        newMessageLength += padBytes;

        // kopijuojam žinutę į naują masyvą 
        final byte[] paddedMessage = new byte[newMessageLength];
        System.arraycopy(message, 0, paddedMessage, 0, message.length);

        // įrašom 1-bitą
        paddedMessage[message.length] = (byte) 0b10000000;

        // įrašom 8 baitų skaičių, aprašantį pradinį žinutės ilgį
        int lenPos = message.length + 1 + padBytes;
        ByteBuffer.wrap(paddedMessage, lenPos, 8).putLong(message.length * 8);

        return paddedMessage;
    }
    /**
     * Iš duoto baitų masyvo padarom skaičių masyvą, kad galėtume atlikti reikalingas operacijas
     * (4 baitai - 1 skaičius).
     *
     * @param bytes pradinis masyvas
     * @return pakeistas masyvas
     */
    public static int[] toIntArray(byte[] bytes)
    {
        if (bytes.length % Integer.BYTES != 0) {
            throw new IllegalArgumentException("byte array length");
        }

        ByteBuffer buf = ByteBuffer.wrap(bytes);

        int[] result = new int[bytes.length / Integer.BYTES];
        for (int i = 0; i < result.length; ++i) {
            result[i] = buf.getInt();
        }

        return result;
    }

    /**
     * Iš duoto skaičių masyvo padarom baitų masyvą, kad galėtume atlikti reikalingas operacijas
     * (1 skaičius - 4 baitai).
     *
     * @param ints pradinis masyvas.
     * @return pakeistas masyvas.
     */
    public static byte[] toByteArray(int[] ints)
    {
        ByteBuffer buf = ByteBuffer.allocate(ints.length * Integer.BYTES);
        for (int i = 0; i < ints.length; ++i) {
            buf.putInt(ints[i]);
        }

        return buf.array();
    }
    // Loginė operacija, reikalinga pagal algoritmo specifikaciją
    private static int ch(int x, int y, int z)
    {
        return (x & y) | ((~x) & z);
    }
    // Loginė operacija, reikalinga pagal algoritmo specifikaciją
    private static int maj(int x, int y, int z)
    {
        return (x & y) | (x & z) | (y & z);
    }
    // Loginė operacija, reikalinga pagal algoritmo specifikaciją
    private static int bigSig0(int x)
    {
        return Integer.rotateRight(x, 2) ^ Integer.rotateRight(x, 13)
                ^ Integer.rotateRight(x, 22);
    }
    // Loginė operacija, reikalinga pagal algoritmo specifikaciją
    private static int bigSig1(int x)
    {
        return Integer.rotateRight(x, 6) ^ Integer.rotateRight(x, 11)
                ^ Integer.rotateRight(x, 25);
    }
    // Loginė operacija, reikalinga pagal algoritmo specifikaciją
    private static int smallSig0(int x)
    {
        return Integer.rotateRight(x, 7) ^ Integer.rotateRight(x, 18)
                ^ (x >>> 3);
    }
    // Loginė operacija, reikalinga pagal algoritmo specifikaciją
    private static int smallSig1(int x)
    {
        return Integer.rotateRight(x, 17) ^ Integer.rotateRight(x, 19)
                ^ (x >>> 10);
    }
    // Pagrindinis metodas, kur paduodame failą, iš kurio skaitysim žinutę 
    public static void main(String[] args) throws IOException {
        File file = new File (args[0]);
        byte[] b = new byte[(int) file.length()];
        FileInputStream fis = new FileInputStream(file);
        fis.read(b);
        fis.close();
        byte[] hashed = Sha224.hash(b);
        byte[] out = Arrays.copyOf(hashed, 28);
        for(int i = 0; i< out.length; ++i) {
            System.out.print(Integer.toHexString(out[i] & 0xff));
        }
        System.out.print("\n");
     
    }

}
