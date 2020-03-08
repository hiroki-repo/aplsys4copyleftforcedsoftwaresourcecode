/*
 This file is part of jpcsp.

 Jpcsp is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 Jpcsp is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with Jpcsp.  If not, see <http://www.gnu.org/licenses/>.
 */
package jpcsp.crypto;

import java.nio.ByteBuffer;

import jpcsp.util.Utilities;

public class KIRK {

    // PSP specific values.
    private int fuseID0;
    private int fuseID1;
    private byte[] priv_iv = new byte[0x10];
    private byte[] prng_data = new byte[0x14];

    // KIRK error values.
    public static final int PSP_KIRK_NOT_ENABLED = 0x1;
    public static final int PSP_KIRK_INVALID_MODE = 0x2;
    public static final int PSP_KIRK_INVALID_HEADER_HASH = 0x3;
    public static final int PSP_KIRK_INVALID_DATA_HASH = 0x4;
    public static final int PSP_KIRK_INVALID_SIG_CHECK = 0x5;
    public static final int PSP_KIRK_UNK1 = 0x6;
    public static final int PSP_KIRK_UNK2 = 0x7;
    public static final int PSP_KIRK_UNK3 = 0x8;
    public static final int PSP_KIRK_UNK4 = 0x9;
    public static final int PSP_KIRK_UNK5 = 0xA;
    public static final int PSP_KIRK_UNK6 = 0xB;
    public static final int PSP_KIRK_NOT_INIT = 0xC;
    public static final int PSP_KIRK_INVALID_OPERATION = 0xD;
    public static final int PSP_KIRK_INVALID_SEED = 0xE;
    public static final int PSP_KIRK_INVALID_SIZE = 0xF;
    public static final int PSP_KIRK_DATA_SIZE_IS_ZERO = 0x10;
    public static final int PSP_SUBCWR_NOT_16_ALGINED = 0x90A;
    public static final int PSP_SUBCWR_HEADER_HASH_INVALID = 0x920;
    public static final int PSP_SUBCWR_BUFFER_TOO_SMALL = 0x1000;

    // KIRK commands.
    public static final int PSP_KIRK_CMD_DECRYPT_PRIVATE = 0x1;         // Master decryption command, used by firmware modules. Applies CMAC checking.
    public static final int PSP_KIRK_CMD_ENCRYPT_SIGN = 0x2;            // Used for key type 3 (blacklisting), encrypts and signs data with a ECDSA signature.
    public static final int PSP_KIRK_CMD_DECRYPT_SIGN = 0x3;            // Used for key type 3 (blacklisting), decrypts and signs data with a ECDSA signature.
    public static final int PSP_KIRK_CMD_ENCRYPT = 0x4;                 // Key table based encryption used for general purposes by several modules.
    public static final int PSP_KIRK_CMD_ENCRYPT_FUSE = 0x5;            // Fuse ID based encryption used for general purposes by several modules.
    public static final int PSP_KIRK_CMD_ENCRYPT_USER = 0x6;            // User specified ID based encryption used for general purposes by several modules.
    public static final int PSP_KIRK_CMD_DECRYPT = 0x7;                 // Key table based decryption used for general purposes by several modules.
    public static final int PSP_KIRK_CMD_DECRYPT_FUSE = 0x8;            // Fuse ID based decryption used for general purposes by several modules.
    public static final int PSP_KIRK_CMD_DECRYPT_USER = 0x9;            // User specified ID based decryption used for general purposes by several modules.
    public static final int PSP_KIRK_CMD_PRIV_SIG_CHECK = 0xA;          // Private signature (SCE) checking command.
    public static final int PSP_KIRK_CMD_SHA1_HASH = 0xB;               // SHA1 hash generating command.
    public static final int PSP_KIRK_CMD_ECDSA_GEN_KEYS = 0xC;          // ECDSA key generating mul1 command. 
    public static final int PSP_KIRK_CMD_ECDSA_MULTIPLY_POINT = 0xD;    // ECDSA key generating mul2 command. 
    public static final int PSP_KIRK_CMD_PRNG = 0xE;                    // Random number generating command. 
    public static final int PSP_KIRK_CMD_INIT = 0xF;                    // KIRK initialization command.
    public static final int PSP_KIRK_CMD_ECDSA_SIGN = 0x10;             // ECDSA signing command.
    public static final int PSP_KIRK_CMD_ECDSA_VERIFY = 0x11;           // ECDSA checking command.
    public static final int PSP_KIRK_CMD_CERT_VERIFY = 0x12;            // Certificate checking command.

    // KIRK command modes.
    public static final int PSP_KIRK_CMD_MODE_CMD1 = 0x1;
    public static final int PSP_KIRK_CMD_MODE_CMD2 = 0x2;
    public static final int PSP_KIRK_CMD_MODE_CMD3 = 0x3;
    public static final int PSP_KIRK_CMD_MODE_ENCRYPT_CBC = 0x4;
    public static final int PSP_KIRK_CMD_MODE_DECRYPT_CBC = 0x5;

    // KIRK header structs.
    private class SHA1_Header {

        private int dataSize;
        private byte[] data;

        public SHA1_Header(ByteBuffer buf) {
            dataSize = buf.getInt();
        }

        private void readData(ByteBuffer buf, int size) {
            data = new byte[size];
            buf.get(data, 0, size);
        }
    }

    private static class AES128_CBC_Header {

        private int mode;
        private int unk1;
        private int unk2;
        private int keySeed;
        private int dataSize;

        public AES128_CBC_Header(ByteBuffer buf) {
            mode = buf.getInt();
            unk1 = buf.getInt();
            unk2 = buf.getInt();
            keySeed = buf.getInt();
            dataSize = buf.getInt();
        }
    }

    private static class AES128_CMAC_Header {

        private byte[] AES128Key = new byte[16];
        private byte[] CMACKey = new byte[16];
        private byte[] CMACHeaderHash = new byte[16];
        private byte[] CMACDataHash = new byte[16];
        private byte[] unk1 = new byte[32];
        private int mode;
        private byte useECDSAhash;
        private byte[] unk2 = new byte[11];
        private int dataSize;
        private int dataOffset;
        private byte[] unk3 = new byte[8];
        private byte[] unk4 = new byte[16];

        public AES128_CMAC_Header(ByteBuffer buf) {
            buf.get(AES128Key, 0, 16);
            buf.get(CMACKey, 0, 16);
            buf.get(CMACHeaderHash, 0, 16);
            buf.get(CMACDataHash, 0, 16);
            buf.get(unk1, 0, 32);
            mode = buf.getInt();
            useECDSAhash = buf.get();
            buf.get(unk2, 0, 11);
            dataSize = buf.getInt();
            dataOffset = buf.getInt();
            buf.get(unk3, 0, 8);
            buf.get(unk4, 0, 16);

            // For PRX, the mode is big-endian, for direct sceKernelUtilsCopyWithRange,
            // the mode is little-endian. I don't know how to better differentiate these cases.
            if ((mode & 0x00FFFFFF) == 0x000000) {
            	mode = Integer.reverseBytes(mode);
            }
        }

        static public int SIZEOF() {
        	return 144;
        }
    }

    private static class AES128_CMAC_ECDSA_Header {

        private byte[] AES128Key = new byte[16];
        private byte[] ECDSAHeaderSig_r = new byte[20];
        private byte[] ECDSAHeaderSig_s = new byte[20];
        private byte[] ECDSADataSig_r = new byte[20];
        private byte[] ECDSADataSig_s = new byte[20];
        private int mode;
        private byte useECDSAhash;
        private byte[] unk1 = new byte[11];
        private int dataSize;
        private int dataOffset;
        private byte[] unk2 = new byte[8];
        private byte[] unk3 = new byte[16];

        public AES128_CMAC_ECDSA_Header(ByteBuffer buf) {
            buf.get(AES128Key, 0, 16);
            buf.get(ECDSAHeaderSig_r, 0, 20);
            buf.get(ECDSAHeaderSig_s, 0, 20);
            buf.get(ECDSADataSig_r, 0, 20);
            buf.get(ECDSADataSig_s, 0, 20);
            mode = buf.getInt();
            useECDSAhash = buf.get();
            buf.get(unk1, 0, 11);
            dataSize = buf.getInt();
            dataOffset = buf.getInt();
            buf.get(unk2, 0, 8);
            buf.get(unk3, 0, 16);
        }
    }

    private static class ECDSASig {

        private byte[] r = new byte[0x14];
        private byte[] s = new byte[0x14];

        private ECDSASig() {
        }
    }

    private static class ECDSAPoint {

        private byte[] x = new byte[0x14];
        private byte[] y = new byte[0x14];

        private ECDSAPoint() {
        }

        private ECDSAPoint(byte[] data) {
            System.arraycopy(data, 0, x, 0, 0x14);
            System.arraycopy(data, 0x14, y, 0, 0x14);
        }

        public byte[] toByteArray() {
            byte[] point = new byte[0x28];
            System.arraycopy(point, 0, x, 0, 0x14);
            System.arraycopy(point, 0x14, y, 0, 0x14);
            return point;
        }
    }

    private static class ECDSAKeygenCtx {

        private byte[] private_key = new byte[0x14];
        private ECDSAPoint public_key;
        private ByteBuffer out;

        private ECDSAKeygenCtx(ByteBuffer output) {
            public_key = new ECDSAPoint();
            out = output;
        }

        public void write() {
            out.put(private_key);
            out.put(public_key.toByteArray());
        }
    }

    private static class ECDSAMultiplyCtx {

        private byte[] multiplier = new byte[0x14];
        private ECDSAPoint public_key = new ECDSAPoint();
        private ByteBuffer out;

        private ECDSAMultiplyCtx(ByteBuffer input, ByteBuffer output) {
            out = output;
            input.get(multiplier, 0, 0x14);
            input.get(public_key.x, 0, 0x14);
            input.get(public_key.y, 0, 0x14);
        }

        public void write() {
            out.put(multiplier);
            out.put(public_key.toByteArray());
        }
    }

    private static class ECDSASignCtx {

        private byte[] enc = new byte[0x20];
        private byte[] hash = new byte[0x14];

        private ECDSASignCtx(ByteBuffer buf) {
            buf.get(enc, 0, 0x20);
            buf.get(hash, 0, 0x14);
        }
    }

    private static class ECDSAVerifyCtx {

        private ECDSAPoint public_key = new ECDSAPoint();
        private byte[] hash = new byte[0x14];
        private ECDSASig sig = new ECDSASig();

        private ECDSAVerifyCtx(ByteBuffer buf) {
            buf.get(public_key.x, 0, 0x14);
            buf.get(public_key.y, 0, 0x14);
            buf.get(hash, 0, 0x14);
            buf.get(sig.r, 0, 0x14);
            buf.get(sig.s, 0, 0x14);
        }
    }

    // Helper functions.
    private static int[] getAESKeyFromSeed(int seed) {
        switch (seed) {
          //all kirk key!
            case 0x00:
            	return new int[] { 0x2C, 0x92, 0xE5, 0x90, 0x2B, 0x86, 0xC1, 0x06, 0xB7, 0x2E, 0xEA, 0x6C, 0xD4, 0xEC, 0x72, 0x48 };
            case 0x01:
            	return new int[] { 0x05, 0x8D, 0xC8, 0x0B, 0x33, 0xA5, 0xBF, 0x9D, 0x56, 0x98, 0xFA, 0xE0, 0xD3, 0x71, 0x5E, 0x1F };
            case 0x02:
            	return new int[] { 0xB8, 0x13, 0xC3, 0x5E, 0xC6, 0x44, 0x41, 0xE3, 0xDC, 0x3C, 0x16, 0xF5, 0xB4, 0x5E, 0x64, 0x84 };
            case 0x03:
            	return new int[] { 0x98, 0x02, 0xC4, 0xE6, 0xEC, 0x9E, 0x9E, 0x2F, 0xFC, 0x63, 0x4C, 0xE4, 0x2F, 0xBB, 0x46, 0x68 };
            case 0x04:
            	return new int[] { 0x99, 0x24, 0x4C, 0xD2, 0x58, 0xF5, 0x1B, 0xCB, 0xB0, 0x61, 0x9C, 0xA7, 0x38, 0x30, 0x07, 0x5F };
            case 0x05:
            	return new int[] { 0x02, 0x25, 0xD7, 0xBA, 0x63, 0xEC, 0xB9, 0x4A, 0x9D, 0x23, 0x76, 0x01, 0xB3, 0xF6, 0xAC, 0x17 };
            case 0x06:
            	return new int[] { 0x60, 0x99, 0xF2, 0x81, 0x70, 0x56, 0x0E, 0x5F, 0x74, 0x7C, 0xB5, 0x20, 0xC0, 0xCD, 0xC2, 0x3C };
            case 0x07:
            	return new int[] { 0x76, 0x36, 0x8B, 0x43, 0x8F, 0x77, 0xD8, 0x7E, 0xFE, 0x5F, 0xB6, 0x11, 0x59, 0x39, 0x88, 0x5C };
            case 0x08:
            	return new int[] { 0x14, 0xA1, 0x15, 0xEB, 0x43, 0x4A, 0x1B, 0xA4, 0x90, 0x5E, 0x03, 0xB6, 0x17, 0xA1, 0x5C, 0x04 };
            case 0x09:
            	return new int[] { 0xE6, 0x58, 0x03, 0xD9, 0xA7, 0x1A, 0xA8, 0x7F, 0x05, 0x9D, 0x22, 0x9D, 0xAF, 0x54, 0x53, 0xD0 };
            case 0x0A:
            	return new int[] { 0xBA, 0x34, 0x80, 0xB4, 0x28, 0xA7, 0xCA, 0x5F, 0x21, 0x64, 0x12, 0xF7, 0x0F, 0xBB, 0x73, 0x23 };
            case 0x0B:
            	return new int[] { 0x72, 0xAD, 0x35, 0xAC, 0x9A, 0xC3, 0x13, 0x0A, 0x77, 0x8C, 0xB1, 0x9D, 0x88, 0x55, 0x0B, 0x0C };
            case 0x0C:
            	return new int[] { 0x84, 0x85, 0xC8, 0x48, 0x75, 0x08, 0x43, 0xBC, 0x9B, 0x9A, 0xEC, 0xA7, 0x9C, 0x7F, 0x60, 0x18 };
            case 0x0D:
            	return new int[] { 0xB5, 0xB1, 0x6E, 0xDE, 0x23, 0xA9, 0x7B, 0x0E, 0xA1, 0x7C, 0xDB, 0xA2, 0xDC, 0xDE, 0xC4, 0x6E };
            case 0x0E:
            	return new int[] { 0xC8, 0x71, 0xFD, 0xB3, 0xBC, 0xC5, 0xD2, 0xF2, 0xE2, 0xD7, 0x72, 0x9D, 0xDF, 0x82, 0x68, 0x82 };
            case 0x0F:
            	return new int[] { 0x0A, 0xBB, 0x33, 0x6C, 0x96, 0xD4, 0xCD, 0xD8, 0xCB, 0x5F, 0x4B, 0xE0, 0xBA, 0xDB, 0x9E, 0x03 };
            case 0x10:
            	return new int[] { 0x32, 0x29, 0x5B, 0xD5, 0xEA, 0xF7, 0xA3, 0x42, 0x16, 0xC8, 0x8E, 0x48, 0xFF, 0x50, 0xD3, 0x71 };
            case 0x11:
            	return new int[] { 0x46, 0xF2, 0x5E, 0x8E, 0x4D, 0x2A, 0xA5, 0x40, 0x73, 0x0B, 0xC4, 0x6E, 0x47, 0xEE, 0x6F, 0x0A };
            case 0x12:
            	return new int[] { 0x5D, 0xC7, 0x11, 0x39, 0xD0, 0x19, 0x38, 0xBC, 0x02, 0x7F, 0xDD, 0xDC, 0xB0, 0x83, 0x7D, 0x9D };
            case 0x13:
            	return new int[] { 0x51, 0xDD, 0x65, 0xF0, 0x71, 0xA4, 0xE5, 0xEA, 0x6A, 0xAF, 0x12, 0x19, 0x41, 0x29, 0xB8, 0xF4 };
            case 0x14:
            	return new int[] { 0x03, 0x76, 0x3C, 0x68, 0x65, 0xC6, 0x9B, 0x0F, 0xFE, 0x8F, 0xD8, 0xEE, 0xA4, 0x36, 0x16, 0xA0 };
            case 0x15:
            	return new int[] { 0x7D, 0x50, 0xB8, 0x5C, 0xAF, 0x67, 0x69, 0xF0, 0xE5, 0x4A, 0xA8, 0x09, 0x8B, 0x0E, 0xBE, 0x1C };
            case 0x16:
            	return new int[] { 0x72, 0x68, 0x4B, 0x32, 0xAC, 0x3B, 0x33, 0x2F, 0x2A, 0x7A, 0xFC, 0x9E, 0x14, 0xD5, 0x6F, 0x6B };
            case 0x17:
            	return new int[] { 0x20, 0x1D, 0x31, 0x96, 0x4A, 0xD9, 0x9F, 0xBF, 0x32, 0xD5, 0xD6, 0x1C, 0x49, 0x1B, 0xD9, 0xFC };
            case 0x18:
            	return new int[] { 0xF8, 0xD8, 0x44, 0x63, 0xD6, 0x10, 0xD1, 0x2A, 0x44, 0x8E, 0x96, 0x90, 0xA6, 0xBB, 0x0B, 0xAD };
            case 0x19:
            	return new int[] { 0x5C, 0xD4, 0x05, 0x7F, 0xA1, 0x30, 0x60, 0x44, 0x0A, 0xD9, 0xB6, 0x74, 0x5F, 0x24, 0x4F, 0x4E };
            case 0x1A:
            	return new int[] { 0xF4, 0x8A, 0xD6, 0x78, 0x59, 0x9C, 0x22, 0xC1, 0xD4, 0x11, 0x93, 0x3D, 0xF8, 0x45, 0xB8, 0x93 };
            case 0x1B:
            	return new int[] { 0xCA, 0xE7, 0xD2, 0x87, 0xA2, 0xEC, 0xC1, 0xCD, 0x94, 0x54, 0x2B, 0x5E, 0x1D, 0x94, 0x88, 0xB2 };
            case 0x1C:
            	return new int[] { 0xDE, 0x26, 0xD3, 0x7A, 0x39, 0x95, 0x6C, 0x2A, 0xD8, 0xC3, 0xA6, 0xAF, 0x21, 0xEB, 0xB3, 0x01 };
            case 0x1D:
            	return new int[] { 0x7C, 0xB6, 0x8B, 0x4D, 0xA3, 0x8D, 0x1D, 0xD9, 0x32, 0x67, 0x9C, 0xA9, 0x9F, 0xFB, 0x28, 0x52 };
            case 0x1E:
            	return new int[] { 0xA0, 0xB5, 0x56, 0xB4, 0x69, 0xAB, 0x36, 0x8F, 0x36, 0xDE, 0xC9, 0x09, 0x2E, 0xCB, 0x41, 0xB1 };
            case 0x1F:
            	return new int[] { 0x93, 0x9D, 0xE1, 0x9B, 0x72, 0x5F, 0xEE, 0xE2, 0x45, 0x2A, 0xBC, 0x17, 0x06, 0xD1, 0x47, 0x69 };
            case 0x20:
            	return new int[] { 0xA4, 0xA4, 0xE6, 0x21, 0x38, 0x2E, 0xF1, 0xAF, 0x7B, 0x17, 0x7A, 0xE8, 0x42, 0xAD, 0x00, 0x31 };
            case 0x21:
            	return new int[] { 0xC3, 0x7F, 0x13, 0xE8, 0xCF, 0x84, 0xDB, 0x34, 0x74, 0x7B, 0xC3, 0xA0, 0xF1, 0x9D, 0x3A, 0x73 };
            case 0x22:
            	return new int[] { 0x2B, 0xF7, 0x83, 0x8A, 0xD8, 0x98, 0xE9, 0x5F, 0xA5, 0xF9, 0x01, 0xDA, 0x61, 0xFE, 0x35, 0xBB };
            case 0x23:
            	return new int[] { 0xC7, 0x04, 0x62, 0x1E, 0x71, 0x4A, 0x66, 0xEA, 0x62, 0xE0, 0x4B, 0x20, 0x3D, 0xB8, 0xC2, 0xE5 };
            case 0x24:
            	return new int[] { 0xC9, 0x33, 0x85, 0x9A, 0xAB, 0x00, 0xCD, 0xCE, 0x4D, 0x8B, 0x8E, 0x9F, 0x3D, 0xE6, 0xC0, 0x0F };
            case 0x25:
            	return new int[] { 0x18, 0x42, 0x56, 0x1F, 0x2B, 0x5F, 0x34, 0xE3, 0x51, 0x3E, 0xB7, 0x89, 0x77, 0x43, 0x1A, 0x65 };
            case 0x26:
            	return new int[] { 0xDC, 0xB0, 0xA0, 0x06, 0x5A, 0x50, 0xA1, 0x4E, 0x59, 0xAC, 0x97, 0x3F, 0x17, 0x58, 0xA3, 0xA3 };
            case 0x27:
            	return new int[] { 0xC4, 0xDB, 0xAE, 0x83, 0xE2, 0x9C, 0xF2, 0x54, 0xA3, 0xDD, 0x37, 0x4E, 0x80, 0x7B, 0xF4, 0x25 };
            case 0x28:
            	return new int[] { 0xBF, 0xAE, 0xEB, 0x49, 0x82, 0x65, 0xC5, 0x7C, 0x64, 0xB8, 0xC1, 0x7E, 0x19, 0x06, 0x44, 0x09 };
            case 0x29:
            	return new int[] { 0x79, 0x7C, 0xEC, 0xC3, 0xB3, 0xEE, 0x0A, 0xC0, 0x3B, 0xD8, 0xE6, 0xC1, 0xE0, 0xA8, 0xB1, 0xA4 };
            case 0x2A:
            	return new int[] { 0x75, 0x34, 0xFE, 0x0B, 0xD6, 0xD0, 0xC2, 0x8D, 0x68, 0xD4, 0xE0, 0x2A, 0xE7, 0xD5, 0xD1, 0x55 };
            case 0x2B:
            	return new int[] { 0xFA, 0xB3, 0x53, 0x26, 0x97, 0x4F, 0x4E, 0xDF, 0xE4, 0xC3, 0xA8, 0x14, 0xC3, 0x2F, 0x0F, 0x88 };
            case 0x2C:
            	return new int[] { 0xEC, 0x97, 0xB3, 0x86, 0xB4, 0x33, 0xC6, 0xBF, 0x4E, 0x53, 0x9D, 0x95, 0xEB, 0xB9, 0x79, 0xE4 };
            case 0x2D:
            	return new int[] { 0xB3, 0x20, 0xA2, 0x04, 0xCF, 0x48, 0x06, 0x29, 0xB5, 0xDD, 0x8E, 0xFC, 0x98, 0xD4, 0x17, 0x7B };
            case 0x2E:
            	return new int[] { 0x5D, 0xFC, 0x0D, 0x4F, 0x2C, 0x39, 0xDA, 0x68, 0x4A, 0x33, 0x74, 0xED, 0x49, 0x58, 0xA7, 0x3A };
            case 0x2F:
            	return new int[] { 0xD7, 0x5A, 0x54, 0x22, 0xCE, 0xD9, 0xA3, 0xD6, 0x2B, 0x55, 0x7D, 0x8D, 0xE8, 0xBE, 0xC7, 0xEC };
            case 0x30:
            	return new int[] { 0x6B, 0x4A, 0xEE, 0x43, 0x45, 0xAE, 0x70, 0x07, 0xCF, 0x8D, 0xCF, 0x4E, 0x4A, 0xE9, 0x3C, 0xFA };
            case 0x31:
            	return new int[] { 0x2B, 0x52, 0x2F, 0x66, 0x4C, 0x2D, 0x11, 0x4C, 0xFE, 0x61, 0x31, 0x8C, 0x56, 0x78, 0x4E, 0xA6 };
            case 0x32:
            	return new int[] { 0x3A, 0xA3, 0x4E, 0x44, 0xC6, 0x6F, 0xAF, 0x7B, 0xFA, 0xE5, 0x53, 0x27, 0xEF, 0xCF, 0xCC, 0x24 };
            case 0x33:
            	return new int[] { 0x2B, 0x5C, 0x78, 0xBF, 0xC3, 0x8E, 0x49, 0x9D, 0x41, 0xC3, 0x3C, 0x5C, 0x7B, 0x27, 0x96, 0xCE };
            case 0x34:
            	return new int[] { 0xF3, 0x7E, 0xEA, 0xD2, 0xC0, 0xC8, 0x23, 0x1D, 0xA9, 0x9B, 0xFA, 0x49, 0x5D, 0xB7, 0x08, 0x1B };
            case 0x35:
            	return new int[] { 0x70, 0x8D, 0x4E, 0x6F, 0xD1, 0xF6, 0x6F, 0x1D, 0x1E, 0x1F, 0xCB, 0x02, 0xF9, 0xB3, 0x99, 0x26 };
            case 0x36:
            	return new int[] { 0x0F, 0x67, 0x16, 0xE1, 0x80, 0x69, 0x9C, 0x51, 0xFC, 0xC7, 0xAD, 0x6E, 0x4F, 0xB8, 0x46, 0xC9 };
            case 0x37:
            	return new int[] { 0x56, 0x0A, 0x49, 0x4A, 0x84, 0x4C, 0x8E, 0xD9, 0x82, 0xEE, 0x0B, 0x6D, 0xC5, 0x7D, 0x20, 0x8D };
            case 0x38:
            	return new int[] { 0x12, 0x46, 0x8D, 0x7E, 0x1C, 0x42, 0x20, 0x9B, 0xBA, 0x54, 0x26, 0x83, 0x5E, 0xB0, 0x33, 0x03 };
            case 0x39:
            	return new int[] { 0xC4, 0x3B, 0xB6, 0xD6, 0x53, 0xEE, 0x67, 0x49, 0x3E, 0xA9, 0x5F, 0xBC, 0x0C, 0xED, 0x6F, 0x8A };
            case 0x3A:
            	return new int[] { 0x2C, 0xC3, 0xCF, 0x8C, 0x28, 0x78, 0xA5, 0xA6, 0x63, 0xE2, 0xAF, 0x2D, 0x71, 0x5E, 0x86, 0xBA };
            case 0x3B:
            	return new int[] { 0x83, 0x3D, 0xA7, 0x0C, 0xED, 0x6A, 0x20, 0x12, 0xD1, 0x96, 0xE6, 0xFE, 0x5C, 0x4D, 0x37, 0xC5 };
            case 0x3C:
            	return new int[] { 0xC7, 0x43, 0xD0, 0x67, 0x42, 0xEE, 0x90, 0xB8, 0xCA, 0x75, 0x50, 0x35, 0x20, 0xAD, 0xBC, 0xCE };
            case 0x3D:
            	return new int[] { 0x8A, 0xE3, 0x66, 0x3F, 0x8D, 0x9E, 0x82, 0xA1, 0xED, 0xE6, 0x8C, 0x9C, 0xE8, 0x25, 0x6D, 0xAA };
            case 0x3E:
            	return new int[] { 0x7F, 0xC9, 0x6F, 0x0B, 0xB1, 0x48, 0x5C, 0xA5, 0x5D, 0xD3, 0x64, 0xB7, 0x7A, 0xF5, 0xE4, 0xEA };
            case 0x3F:
            	return new int[] { 0x91, 0xB7, 0x65, 0x78, 0x8B, 0xCB, 0x8B, 0xD4, 0x02, 0xED, 0x55, 0x3A, 0x66, 0x62, 0xD0, 0xAD };
            case 0x40:
            	return new int[] { 0x28, 0x24, 0xF9, 0x10, 0x1B, 0x8D, 0x0F, 0x7B, 0x6E, 0xB2, 0x63, 0xB5, 0xB5, 0x5B, 0x2E, 0xBB };
            case 0x41:
            	return new int[] { 0x30, 0xE2, 0x57, 0x5D, 0xE0, 0xA2, 0x49, 0xCE, 0xE8, 0xCF, 0x2B, 0x5E, 0x4D, 0x9F, 0x52, 0xC7 };
            case 0x42:
            	return new int[] { 0x5E, 0xE5, 0x04, 0x39, 0x62, 0x32, 0x02, 0xFA, 0x85, 0x39, 0x3F, 0x72, 0xBB, 0x77, 0xFD, 0x1A };
            case 0x43:
            	return new int[] { 0xF8, 0x81, 0x74, 0xB1, 0xBD, 0xE9, 0xBF, 0xDD, 0x45, 0xE2, 0xF5, 0x55, 0x89, 0xCF, 0x46, 0xAB };
            case 0x44:
            	return new int[] { 0x7D, 0xF4, 0x92, 0x65, 0xE3, 0xFA, 0xD6, 0x78, 0xD6, 0xFE, 0x78, 0xAD, 0xBB, 0x3D, 0xFB, 0x63 };
            case 0x45:
            	return new int[] { 0x74, 0x7F, 0xD6, 0x2D, 0xC7, 0xA1, 0xCA, 0x96, 0xE2, 0x7A, 0xCE, 0xFF, 0xAA, 0x72, 0x3F, 0xF7 };
            case 0x46:
            	return new int[] { 0x1E, 0x58, 0xEB, 0xD0, 0x65, 0xBB, 0xF1, 0x68, 0xC5, 0xBD, 0xF7, 0x46, 0xBA, 0x7B, 0xE1, 0x00 };
            case 0x47:
            	return new int[] { 0x24, 0x34, 0x7D, 0xAF, 0x5E, 0x4B, 0x35, 0x72, 0x7A, 0x52, 0x27, 0x6B, 0xA0, 0x54, 0x74, 0xDB };
            case 0x48:
            	return new int[] { 0x09, 0xB1, 0xC7, 0x05, 0xC3, 0x5F, 0x53, 0x66, 0x77, 0xC0, 0xEB, 0x36, 0x77, 0xDF, 0x83, 0x07 };
            case 0x49:
            	return new int[] { 0xCC, 0xBE, 0x61, 0x5C, 0x05, 0xA2, 0x00, 0x33, 0x37, 0x8E, 0x59, 0x64, 0xA7, 0xDD, 0x70, 0x3D };
            case 0x4A:
            	return new int[] { 0x0D, 0x47, 0x50, 0xBB, 0xFC, 0xB0, 0x02, 0x81, 0x30, 0xE1, 0x84, 0xDE, 0xA8, 0xD4, 0x84, 0x13 };
            case 0x4B:
            	return new int[] { 0x0C, 0xFD, 0x67, 0x9A, 0xF9, 0xB4, 0x72, 0x4F, 0xD7, 0x8D, 0xD6, 0xE9, 0x96, 0x42, 0x28, 0x8B };
            case 0x4C:
            	return new int[] { 0x7A, 0xD3, 0x1A, 0x8B, 0x4B, 0xEF, 0xC2, 0xC2, 0xB3, 0x99, 0x01, 0xA9, 0xFE, 0x76, 0xB9, 0x87 };
            case 0x4D:
            	return new int[] { 0xBE, 0x78, 0x78, 0x17, 0xC7, 0xF1, 0x6F, 0x1A, 0xE0, 0xEF, 0x3B, 0xDE, 0x4C, 0xC2, 0xD7, 0x86 };
            case 0x4E:
            	return new int[] { 0x7C, 0xD8, 0xB8, 0x91, 0x91, 0x0A, 0x43, 0x14, 0xD0, 0x53, 0x3D, 0xD8, 0x4C, 0x45, 0xBE, 0x16 };
            case 0x4F:
            	return new int[] { 0x32, 0x72, 0x2C, 0x88, 0x07, 0xCF, 0x35, 0x7D, 0x4A, 0x2F, 0x51, 0x19, 0x44, 0xAE, 0x68, 0xDA };
            case 0x50:
            	return new int[] { 0x7E, 0x6B, 0xBF, 0xF6, 0xF6, 0x87, 0xB8, 0x98, 0xEE, 0xB5, 0x1B, 0x32, 0x16, 0xE4, 0x6E, 0x5D };
            case 0x51:
            	return new int[] { 0x08, 0xEA, 0x5A, 0x83, 0x49, 0xB5, 0x9D, 0xB5, 0x3E, 0x07, 0x79, 0xB1, 0x9A, 0x59, 0xA3, 0x54 };
            case 0x52:
            	return new int[] { 0xF3, 0x12, 0x81, 0xBF, 0xE6, 0x9F, 0x51, 0xD1, 0x64, 0x08, 0x25, 0x21, 0xFF, 0xBB, 0x22, 0x61 };
            case 0x53:
            	return new int[] { 0xAF, 0xFE, 0x8E, 0xB1, 0x3D, 0xD1, 0x7E, 0xD8, 0x0A, 0x61, 0x24, 0x1C, 0x95, 0x92, 0x56, 0xB6 };
            case 0x54:
            	return new int[] { 0x92, 0xCD, 0xB4, 0xC2, 0x5B, 0xF2, 0x35, 0x5A, 0x23, 0x09, 0xE8, 0x19, 0xC9, 0x14, 0x42, 0x35 };
            case 0x55:
            	return new int[] { 0xE1, 0xC6, 0x5B, 0x22, 0x6B, 0xE1, 0xDA, 0x02, 0xBA, 0x18, 0xFA, 0x21, 0x34, 0x9E, 0xF9, 0x6D };
            case 0x56:
            	return new int[] { 0x14, 0xEC, 0x76, 0xCE, 0x97, 0xF3, 0x8A, 0x0A, 0x34, 0x50, 0x6C, 0x53, 0x9A, 0x5C, 0x9A, 0xB4 };
            case 0x57:
            	return new int[] { 0x1C, 0x9B, 0xC4, 0x90, 0xE3, 0x06, 0x64, 0x81, 0xFA, 0x59, 0xFD, 0xB6, 0x00, 0xBB, 0x28, 0x70 };
            case 0x58:
            	return new int[] { 0x43, 0xA5, 0xCA, 0xCC, 0x0D, 0x6C, 0x2D, 0x3F, 0x2B, 0xD9, 0x89, 0x67, 0x6B, 0x3F, 0x7F, 0x57 };
            case 0x59:
            	return new int[] { 0x00, 0xEF, 0xFD, 0x18, 0x08, 0xA4, 0x05, 0x89, 0x3C, 0x38, 0xFB, 0x25, 0x72, 0x70, 0x61, 0x06 };
            case 0x5A:
            	return new int[] { 0xEE, 0xAF, 0x49, 0xE0, 0x09, 0x87, 0x9B, 0xEF, 0xAA, 0xD6, 0x32, 0x6A, 0x32, 0x13, 0xC4, 0x29 };
            case 0x5B:
            	return new int[] { 0x8D, 0x26, 0xB9, 0x0F, 0x43, 0x1D, 0xBB, 0x08, 0xDB, 0x1D, 0xDA, 0xC5, 0xB5, 0x2C, 0x92, 0xED };
            case 0x5C:
            	return new int[] { 0x57, 0x7C, 0x30, 0x60, 0xAE, 0x6E, 0xBE, 0xAE, 0x3A, 0xAB, 0x18, 0x19, 0xC5, 0x71, 0x68, 0x0B };
            case 0x5D:
            	return new int[] { 0x11, 0x5A, 0x5D, 0x20, 0xD5, 0x3A, 0x8D, 0xD3, 0x9C, 0xC5, 0xAF, 0x41, 0x0F, 0x0F, 0x18, 0x6F };
            case 0x5E:
            	return new int[] { 0x0D, 0x4D, 0x51, 0xAB, 0x23, 0x79, 0xBF, 0x80, 0x3A, 0xBF, 0xB9, 0x0E, 0x75, 0xFC, 0x14, 0xBF };
            case 0x5F:
            	return new int[] { 0x99, 0x93, 0xDA, 0x3E, 0x7D, 0x2E, 0x5B, 0x15, 0xF2, 0x52, 0xA4, 0xE6, 0x6B, 0xB8, 0x5A, 0x98 };
            case 0x60:
            	return new int[] { 0xF4, 0x28, 0x30, 0xA5, 0xFB, 0x0D, 0x8D, 0x76, 0x0E, 0xA6, 0x71, 0xC2, 0x2B, 0xDE, 0x66, 0x9D };
            case 0x61:
            	return new int[] { 0xFB, 0x5F, 0xEB, 0x7F, 0xC7, 0xDC, 0xDD, 0x69, 0x37, 0x01, 0x97, 0x9B, 0x29, 0x03, 0x5C, 0x47 };
            case 0x62:
            	return new int[] { 0x02, 0x32, 0x6A, 0xE7, 0xD3, 0x96, 0xCE, 0x7F, 0x1C, 0x41, 0x9D, 0xD6, 0x52, 0x07, 0xED, 0x09 };
            case 0x63:
            	return new int[] { 0x9C, 0x9B, 0x13, 0x72, 0xF8, 0xC6, 0x40, 0xCF, 0x1C, 0x62, 0xF5, 0xD5, 0x92, 0xDD, 0xB5, 0x82 };
            case 0x64:
            	return new int[] { 0x03, 0xB3, 0x02, 0xE8, 0x5F, 0xF3, 0x81, 0xB1, 0x3B, 0x8D, 0xAA, 0x2A, 0x90, 0xFF, 0x5E, 0x61 };
            case 0x65:
            	return new int[] { 0xBC, 0xD7, 0xF9, 0xD3, 0x2F, 0xAC, 0xF8, 0x47, 0xC0, 0xFB, 0x4D, 0x2F, 0x30, 0x9A, 0xBD, 0xA6 };
            case 0x66:
            	return new int[] { 0xF5, 0x55, 0x96, 0xE9, 0x7F, 0xAF, 0x86, 0x7F, 0xAC, 0xB3, 0x3A, 0xE6, 0x9C, 0x8B, 0x6F, 0x93 };
            case 0x67:
            	return new int[] { 0xEE, 0x29, 0x70, 0x93, 0xF9, 0x4E, 0x44, 0x59, 0x44, 0x17, 0x1F, 0x8E, 0x86, 0xE1, 0x70, 0xFC };
            case 0x68:
            	return new int[] { 0xE4, 0x34, 0x52, 0x0C, 0xF0, 0x88, 0xCF, 0xC8, 0xCD, 0x78, 0x1B, 0x6C, 0xCF, 0x8C, 0x48, 0xC4 };
            case 0x69:
            	return new int[] { 0xC1, 0xBF, 0x66, 0x81, 0x8E, 0xF9, 0x53, 0xF2, 0xE1, 0x26, 0x6B, 0x6F, 0x55, 0x0C, 0xC9, 0xCD };
            case 0x6A:
            	return new int[] { 0x56, 0x0F, 0xFF, 0x8F, 0x3C, 0x96, 0x49, 0x14, 0x45, 0x16, 0xF1, 0xBC, 0xBF, 0xCE, 0xA3, 0x0C };
            case 0x6B:
            	return new int[] { 0x24, 0x08, 0xDC, 0x75, 0x37, 0x60, 0xA2, 0x9F, 0x05, 0x54, 0xB5, 0xF2, 0x43, 0x85, 0x73, 0x99 };
            case 0x6C:
            	return new int[] { 0xDD, 0xD5, 0xB5, 0x6A, 0x59, 0xC5, 0x5A, 0xE8, 0x3B, 0x96, 0x67, 0xC7, 0x5C, 0x2A, 0xE2, 0xDC };
            case 0x6D:
            	return new int[] { 0xAA, 0x68, 0x67, 0x72, 0xE0, 0x2D, 0x44, 0xD5, 0xCD, 0xBB, 0x65, 0x04, 0xBC, 0xD5, 0xBF, 0x4E };
            case 0x6E:
            	return new int[] { 0x1F, 0x17, 0xF0, 0x14, 0xE7, 0x77, 0xA2, 0xFE, 0x4B, 0x13, 0x6B, 0x56, 0xCD, 0x7E, 0xF7, 0xE9 };
            case 0x6F:
            	return new int[] { 0xC9, 0x35, 0x48, 0xCF, 0x55, 0x8D, 0x75, 0x03, 0x89, 0x6B, 0x2E, 0xEB, 0x61, 0x8C, 0xA9, 0x02 };
            case 0x70:
            	return new int[] { 0xDE, 0x34, 0xC5, 0x41, 0xE7, 0xCA, 0x86, 0xE8, 0xBE, 0xA7, 0xC3, 0x1C, 0xEC, 0xE4, 0x36, 0x0F };
            case 0x71:
            	return new int[] { 0xDD, 0xE5, 0xFF, 0x55, 0x1B, 0x74, 0xF6, 0xF4, 0xE0, 0x16, 0xD7, 0xAB, 0x22, 0x31, 0x1B, 0x6A };
            case 0x72:
            	return new int[] { 0xB0, 0xE9, 0x35, 0x21, 0x33, 0x3F, 0xD7, 0xBA, 0xB4, 0x76, 0x2C, 0xCB, 0x4D, 0x80, 0x08, 0xD8 };
            case 0x73:
            	return new int[] { 0x38, 0x14, 0x69, 0xC4, 0xC3, 0xF9, 0x1B, 0x96, 0x33, 0x63, 0x8E, 0x4D, 0x5F, 0x3D, 0xF0, 0x29 };
            case 0x74:
            	return new int[] { 0xFA, 0x48, 0x6A, 0xD9, 0x8E, 0x67, 0x16, 0xEF, 0x6A, 0xB0, 0x87, 0xF5, 0x89, 0x45, 0x7F, 0x2A };
            case 0x75:
            	return new int[] { 0x32, 0x1A, 0x09, 0x12, 0x50, 0x14, 0x8A, 0x3E, 0x96, 0x3D, 0xEA, 0x02, 0x59, 0x32, 0xE1, 0x8F };
            case 0x76:
            	return new int[] { 0x4B, 0x00, 0xBE, 0x29, 0xBC, 0xB0, 0x28, 0x64, 0xCE, 0xFD, 0x43, 0xA9, 0x6F, 0xD9, 0x5C, 0xED };
            case 0x77:
            	return new int[] { 0x57, 0x7D, 0xC4, 0xFF, 0x02, 0x44, 0xE2, 0x80, 0x91, 0xF4, 0xCA, 0x0A, 0x75, 0x69, 0xFD, 0xA8 };
            case 0x78:
            	return new int[] { 0x83, 0x53, 0x36, 0xC6, 0x18, 0x03, 0xE4, 0x3E, 0x4E, 0xB3, 0x0F, 0x6B, 0x6E, 0x79, 0x9B, 0x7A };
            case 0x79:
            	return new int[] { 0x5C, 0x92, 0x65, 0xFD, 0x7B, 0x59, 0x6A, 0xA3, 0x7A, 0x2F, 0x50, 0x9D, 0x85, 0xE9, 0x27, 0xF8 };
            case 0x7A:
            	return new int[] { 0x9A, 0x39, 0xFB, 0x89, 0xDF, 0x55, 0xB2, 0x60, 0x14, 0x24, 0xCE, 0xA6, 0xD9, 0x65, 0x0A, 0x9D };
            case 0x7B:
            	return new int[] { 0x8B, 0x75, 0xBE, 0x91, 0xA8, 0xC7, 0x5A, 0xD2, 0xD7, 0xA5, 0x94, 0xA0, 0x1C, 0xBB, 0x95, 0x91 };
            case 0x7C:
            	return new int[] { 0x95, 0xC2, 0x1B, 0x8D, 0x05, 0xAC, 0xF5, 0xEC, 0x5A, 0xEE, 0x77, 0x81, 0x23, 0x95, 0xC4, 0xD7 };
            case 0x7D:
            	return new int[] { 0xB9, 0xA4, 0x61, 0x64, 0x36, 0x33, 0xFA, 0x5D, 0x94, 0x88, 0xE2, 0xD3, 0x28, 0x1E, 0x01, 0xA2 };
            case 0x7E:
            	return new int[] { 0xB8, 0xB0, 0x84, 0xFB, 0x9F, 0x4C, 0xFA, 0xF7, 0x30, 0xFE, 0x73, 0x25, 0xA2, 0xAB, 0x89, 0x7D };
            case 0x7F:
            	return new int[] { 0x5F, 0x8C, 0x17, 0x9F, 0xC1, 0xB2, 0x1D, 0xF1, 0xF6, 0x36, 0x7A, 0x9C, 0xF7, 0xD3, 0xD4, 0x7C };
/*            case 0x00:
            	return new int[] { 0x2C, 0x92, 0xE5, 0x90, 0x2B, 0x86, 0xC1, 0x06, 0xB7, 0x2E, 0xEA, 0x6C, 0xD4, 0xEC, 0x72, 0x48 };
            case 0x01:
            	return new int[] { 0x05, 0x8D, 0xC8, 0x0B, 0x33, 0xA5, 0xBF, 0x9D, 0x56, 0x98, 0xFA, 0xE0, 0xD3, 0x71, 0x5E, 0x1F };
            case 0x02:
                return KeyVault.kirkAESKey20;
            case 0x03:
                return KeyVault.kirkAESKey1;
            case 0x04:
                return KeyVault.kirkAESKey2;
            case 0x05:
                return KeyVault.kirkAESKey3;
            case 0x06:
            	return new int[] { 0x60, 0x99, 0xF2, 0x81, 0x70, 0x56, 0x0E, 0x5F, 0x74, 0x7C, 0xB5, 0x20, 0xC0, 0xCD, 0xC2, 0x3C };
            case 0x07:
                return KeyVault.kirkAESKey21;
            case 0x08:
            	return new int[] { 0x14, 0xA1, 0x15, 0xEB, 0x43, 0x4A, 0x1B, 0xA4, 0x90, 0x5E, 0x03, 0xB6, 0x17, 0xA1, 0x5C, 0x04 };
            case 0x09:
            	return new int[] { 0xE6, 0x58, 0x03, 0xD9, 0xA7, 0x1A, 0xA8, 0x7F, 0x05, 0x9D, 0x22, 0x9D, 0xAF, 0x54, 0x53, 0xD0 };
            case 0x0A:
            	return new int[] { 0xBA, 0x34, 0x80, 0xB4, 0x28, 0xA7, 0xCA, 0x5F, 0x21, 0x64, 0x12, 0xF7, 0x0F, 0xBB, 0x73, 0x23 };
            case 0x0B:
            	return new int[] { 0x72, 0xAD, 0x35, 0xAC, 0x9A, 0xC3, 0x13, 0x0A, 0x77, 0x8C, 0xB1, 0x9D, 0x88, 0x55, 0x0B, 0x0C };
            case 0x0C:
                return KeyVault.kirkAESKey4;
            case 0x0D:
                return KeyVault.kirkAESKey5;
            case 0x0E:
                return KeyVault.kirkAESKey6;
            case 0x0F:
                return KeyVault.kirkAESKey7;
            case 0x10:
                return KeyVault.kirkAESKey8;
            case 0x11:
                return KeyVault.kirkAESKey9;
            case 0x12:
                return KeyVault.kirkAESKey10;
            case 0x13:
            	return new int[] { 0x51, 0xDD, 0x65, 0xF0, 0x71, 0xA4, 0xE5, 0xEA, 0x6A, 0xAF, 0x12, 0x19, 0x41, 0x29, 0xB8, 0xF4 };
            case 0x25:
            	return new int[] { 0x18, 0x42, 0x56, 0x1F, 0x2B, 0x5F, 0x34, 0xE3, 0x51, 0x3E, 0xB7, 0x89, 0x77, 0x43, 0x1A, 0x65 };
            case 0x38:
                return KeyVault.kirkAESKey11;
            case 0x39:
                return KeyVault.kirkAESKey12;
            case 0x3A:
                return KeyVault.kirkAESKey13;
            case 0x44:
                return KeyVault.kirkAESKey22;
            case 0x4B:
                return KeyVault.kirkAESKey14;
            case 0x53:
                return KeyVault.kirkAESKey15;
            case 0x57:
                return KeyVault.kirkAESKey16;
            case 0x5D:
                return KeyVault.kirkAESKey17;
            case 0x60:
            	return new int[] { 0xF4, 0x28, 0x30, 0xA5, 0xFB, 0x0D, 0x8D, 0x76, 0x0E, 0xA6, 0x71, 0xC2, 0x2B, 0xDE, 0x66, 0x9D };
            case 0x63:
                return KeyVault.kirkAESKey18;
            case 0x64:
                return KeyVault.kirkAESKey19;
            case 0x7F:
            	return new int[] { 0x5F, 0x8C, 0x17, 0x9F, 0xC1, 0xB2, 0x1D, 0xF1, 0xF6, 0x36, 0x7A, 0x9C, 0xF7, 0xD3, 0xD4, 0x7C };*/
            default:
                return null;
        }
    }

    public KIRK() {
    }

    public KIRK(byte[] seed, int seedLength, int fuseid0, int fuseid1) {
        // Set up the data for the pseudo random number generator using a
        // seed set by the user.
        byte[] temp = new byte[0x104];
        temp[0] = 0;
        temp[1] = 0;
        temp[2] = 1;
        temp[3] = 0;

        ByteBuffer bTemp = ByteBuffer.wrap(temp);
        ByteBuffer bPRNG = ByteBuffer.wrap(prng_data);

        // Random data to act as a key.
        byte[] key = {(byte) 0x07, (byte) 0xAB, (byte) 0xEF, (byte) 0xF8, (byte) 0x96,
            (byte) 0x8C, (byte) 0xF3, (byte) 0xD6, (byte) 0x14, (byte) 0xE0, (byte) 0xEB, (byte) 0xB2,
            (byte) 0x9D, (byte) 0x8B, (byte) 0x4E, (byte) 0x74};

        // Direct call to get the system time.
        int systime = (int) System.currentTimeMillis();

        // Generate a SHA-1 hash for the PRNG.
        if (seedLength > 0) {
            byte[] seedBuf = new byte[seedLength + 4];
            ByteBuffer bSeedBuf = ByteBuffer.wrap(seedBuf);
            
            SHA1_Header seedHeader = new SHA1_Header(bSeedBuf);
            bSeedBuf.rewind();
            
            seedHeader.dataSize = seedLength;
            executeKIRKCmd11(bPRNG, bSeedBuf, seedLength + 4);
        }

        // Use the system time for randomness.
        System.arraycopy(prng_data, 0, temp, 4, 0x14);
        temp[0x18] = (byte) (systime & 0xFF);
        temp[0x19] = (byte) ((systime >> 8) & 0xFF);
        temp[0x1A] = (byte) ((systime >> 16) & 0xFF);
        temp[0x1B] = (byte) ((systime >> 24) & 0xFF);

        // Set the final PRNG number.
        System.arraycopy(key, 0, temp, 0x1C, 0x10);
        bPRNG.clear();
        executeKIRKCmd11(bPRNG, bTemp, 0x104);

        fuseID0 = fuseid0;
        fuseID1 = fuseid1;
    }

    /*
     * KIRK commands: main emulated crypto functions.
     */
    // Decrypt with AESCBC128-CMAC header and sig check.
    private int executeKIRKCmd1(ByteBuffer out, ByteBuffer in, int size) {
        // Return an error if the crypto engine hasn't been initialized.
        if (!CryptoEngine.getCryptoEngineStatus()) {
            return PSP_KIRK_NOT_INIT;
        }

        int outPosition = out.position();

        // Copy the input for sig check.
        ByteBuffer sigIn = in.duplicate();
        sigIn.order(in.order()); // duplicate() does not copy the order()

        int headerSize = AES128_CMAC_Header.SIZEOF();
        int headerOffset = in.position();

        // Read in the CMD1 format header.
        AES128_CMAC_Header header = new AES128_CMAC_Header(in);

        if (header.mode != PSP_KIRK_CMD_MODE_CMD1) {
            return PSP_KIRK_INVALID_MODE;  // Only valid for mode CMD1.
        }

        // Start AES128 processing.
        AES128 aes = new AES128("AES/CBC/NoPadding");

        // Convert the AES CMD1 key into a real byte array for SecretKeySpec.
        byte[] k = new byte[16];
        for (int i = 0; i < KeyVault.kirkAESKey0.length; i++) {
            k[i] = (byte) KeyVault.kirkAESKey0[i];
        }

        // Decrypt and extract the new AES and CMAC keys from the top of the data.
        byte[] encryptedKeys = new byte[32];
        System.arraycopy(header.AES128Key, 0, encryptedKeys, 0, 16);
        System.arraycopy(header.CMACKey, 0, encryptedKeys, 16, 16);
        byte[] decryptedKeys = aes.decrypt(encryptedKeys, k, priv_iv);

        // Check for a valid signature.
        int sigCheck = executeKIRKCmd10(sigIn, size);

        if (decryptedKeys == null) {
            // Only return the sig check result if the keys are invalid
            // to allow skipping the CMAC comparision.
            // TODO: Trace why the CMAC hashes aren't matching.
            return sigCheck;
        }

        // Get the newly decrypted AES key and proceed with the
        // full data decryption.
        byte[] aesBuf = new byte[16];
        System.arraycopy(decryptedKeys, 0, aesBuf, 0, aesBuf.length);

        // Extract the final ELF params.
        int elfDataSize = header.dataSize;
        int elfDataOffset = header.dataOffset;

        // Input buffer for decryption must have a length aligned on 16 bytes
        int paddedElfDataSize = Utilities.alignUp(elfDataSize, 15);

        // Decrypt all the ELF data.
        byte[] inBuf = new byte[paddedElfDataSize];
        System.arraycopy(in.array(), elfDataOffset + headerOffset + headerSize, inBuf, 0, paddedElfDataSize);
        byte[] outBuf = aes.decrypt(inBuf, aesBuf, priv_iv);

        out.position(outPosition);
        out.put(outBuf);
        out.limit(elfDataSize);
        in.clear();

        return 0;
    }

    // Encrypt with AESCBC128 using keys from table.
    private int executeKIRKCmd4(ByteBuffer out, ByteBuffer in, int size) {
        // Return an error if the crypto engine hasn't been initialized.
        if (!CryptoEngine.getCryptoEngineStatus()) {
            return PSP_KIRK_NOT_INIT;
        }

        int outPosition = out.position();

        // Read in the CMD4 format header.
        AES128_CBC_Header header = new AES128_CBC_Header(in);

        if (header.mode != PSP_KIRK_CMD_MODE_ENCRYPT_CBC) {
            return PSP_KIRK_INVALID_MODE;  // Only valid for mode ENCRYPT_CBC.
        }

        if (header.dataSize == 0) {
            return PSP_KIRK_DATA_SIZE_IS_ZERO;
        }

        int[] key = getAESKeyFromSeed(header.keySeed);
        if (key == null) {
            return PSP_KIRK_INVALID_SEED;
        }

        byte[] encKey = new byte[16];
        for (int i = 0; i < encKey.length; i++) {
            encKey[i] = (byte) key[i];
        }

        AES128 aes = new AES128("AES/CBC/NoPadding");

        byte[] inBuf = new byte[header.dataSize];
        in.get(inBuf, 0, header.dataSize);
        byte[] outBuf = aes.encrypt(inBuf, encKey, priv_iv);

        out.position(outPosition);
        // The header is kept in the output and the header.mode is even updated from
        // PSP_KIRK_CMD_MODE_ENCRYPT_CBC to PSP_KIRK_CMD_MODE_DECRYPT_CBC.
        out.putInt(PSP_KIRK_CMD_MODE_DECRYPT_CBC);
        out.putInt(header.unk1);
        out.putInt(header.unk2);
        out.putInt(header.keySeed);
        out.putInt(header.dataSize);
        out.put(outBuf);
        in.clear();

        return 0;
    }

    // Encrypt with AESCBC128 using keys from table.
    private int executeKIRKCmd5(ByteBuffer out, ByteBuffer in, int size) {
        // Return an error if the crypto engine hasn't been initialized.
        if (!CryptoEngine.getCryptoEngineStatus()) {
            return PSP_KIRK_NOT_INIT;
        }

        int outPosition = out.position();

        // Read in the CMD4 format header.
        AES128_CBC_Header header = new AES128_CBC_Header(in);

        if (header.mode != PSP_KIRK_CMD_MODE_ENCRYPT_CBC) {
            return PSP_KIRK_INVALID_MODE;  // Only valid for mode ENCRYPT_CBC.
        }

        if (header.dataSize == 0) {
            return PSP_KIRK_DATA_SIZE_IS_ZERO;
        }

        byte[] key = null;
        if (header.keySeed == 0x100) {
            key = priv_iv;
        } else {
            return PSP_KIRK_INVALID_SIZE; // Dummy.
        }

        byte[] encKey = new byte[16];
        for (int i = 0; i < encKey.length; i++) {
            encKey[i] = (byte) key[i];
        }

        AES128 aes = new AES128("AES/CBC/NoPadding");

        byte[] inBuf = new byte[header.dataSize];
        in.get(inBuf, 0, header.dataSize);
        byte[] outBuf = aes.encrypt(inBuf, encKey, priv_iv);

        out.position(outPosition);
        // The header is kept in the output and the header.mode is even updated from
        // PSP_KIRK_CMD_MODE_ENCRYPT_CBC to PSP_KIRK_CMD_MODE_DECRYPT_CBC.
        out.putInt(PSP_KIRK_CMD_MODE_DECRYPT_CBC);
        out.putInt(header.unk1);
        out.putInt(header.unk2);
        out.putInt(header.keySeed);
        out.putInt(header.dataSize);
        out.put(outBuf);
        in.clear();

        return 0;
    }

    // Decrypt with AESCBC128 using keys from table.
    private int executeKIRKCmd7(ByteBuffer out, ByteBuffer in, int size) {
        // Return an error if the crypto engine hasn't been initialized.
        if (!CryptoEngine.getCryptoEngineStatus()) {
            return PSP_KIRK_NOT_INIT;
        }

        int outPosition = out.position();

        // Read in the CMD7 format header.
        AES128_CBC_Header header = new AES128_CBC_Header(in);

        if (header.mode != PSP_KIRK_CMD_MODE_DECRYPT_CBC) {
            return PSP_KIRK_INVALID_MODE;  // Only valid for mode DECRYPT_CBC.
        }

        if (header.dataSize == 0) {
            return PSP_KIRK_DATA_SIZE_IS_ZERO;
        }

        int[] key = getAESKeyFromSeed(header.keySeed);
        if (key == null) {
            return PSP_KIRK_INVALID_SEED;
        }

        byte[] decKey = new byte[16];
        for (int i = 0; i < decKey.length; i++) {
            decKey[i] = (byte) key[i];
        }

        AES128 aes = new AES128("AES/CBC/NoPadding");

        byte[] inBuf = new byte[header.dataSize];
        in.get(inBuf, 0, header.dataSize);
        byte[] outBuf = aes.decrypt(inBuf, decKey, priv_iv);

        out.position(outPosition);
        out.put(outBuf);
        in.clear();

        return 0;
    }

    // Decrypt with AESCBC128 using keys from table.
    private int executeKIRKCmd8(ByteBuffer out, ByteBuffer in, int size) {
        // Return an error if the crypto engine hasn't been initialized.
        if (!CryptoEngine.getCryptoEngineStatus()) {
            return PSP_KIRK_NOT_INIT;
        }

        int outPosition = out.position();

        // Read in the CMD7 format header.
        AES128_CBC_Header header = new AES128_CBC_Header(in);

        if (header.mode != PSP_KIRK_CMD_MODE_DECRYPT_CBC) {
            return PSP_KIRK_INVALID_MODE;  // Only valid for mode DECRYPT_CBC.
        }

        if (header.dataSize == 0) {
            return PSP_KIRK_DATA_SIZE_IS_ZERO;
        }

        byte[] key = null;
        if (header.keySeed == 0x100) {
            key = priv_iv;
        } else {
            return PSP_KIRK_INVALID_SIZE; // Dummy.
        }

        byte[] decKey = new byte[16];
        for (int i = 0; i < decKey.length; i++) {
            decKey[i] = (byte) key[i];
        }

        AES128 aes = new AES128("AES/CBC/NoPadding");

        byte[] inBuf = new byte[header.dataSize];
        in.get(inBuf, 0, header.dataSize);
        byte[] outBuf = aes.decrypt(inBuf, decKey, priv_iv);

        out.position(outPosition);
        out.put(outBuf);
        in.clear();

        return 0;
    }

    // CMAC Sig check.
    private int executeKIRKCmd10(ByteBuffer in, int size) {
        // Return an error if the crypto engine hasn't been initialized.
        if (!CryptoEngine.getCryptoEngineStatus()) {
            return PSP_KIRK_NOT_INIT;
        }

        int headerOffset = in.position();

        // Read in the CMD10 format header.
        AES128_CMAC_Header header = new AES128_CMAC_Header(in);
        if ((header.mode != PSP_KIRK_CMD_MODE_CMD1)
                && (header.mode != PSP_KIRK_CMD_MODE_CMD2)
                && (header.mode != PSP_KIRK_CMD_MODE_CMD3)) {
            return PSP_KIRK_INVALID_MODE;  // Only valid for modes CMD1, CMD2 and CMD3.
        }

        if (header.dataSize == 0) {
            return PSP_KIRK_DATA_SIZE_IS_ZERO;
        }

        AES128 aes = new AES128("AES/CBC/NoPadding");

        // Convert the AES CMD1 key into a real byte array.
        byte[] k = new byte[16];
        for (int i = 0; i < KeyVault.kirkAESKey0.length; i++) {
            k[i] = (byte) KeyVault.kirkAESKey0[i];
        }

        // Decrypt and extract the new AES and CMAC keys from the top of the data.
        byte[] encryptedKeys = new byte[32];
        System.arraycopy(header.AES128Key, 0, encryptedKeys, 0, 16);
        System.arraycopy(header.CMACKey, 0, encryptedKeys, 16, 16);
        byte[] decryptedKeys = aes.decrypt(encryptedKeys, k, priv_iv);

        byte[] cmacHeaderHash = new byte[16];
        byte[] cmacDataHash = new byte[16];

        byte[] cmacBuf = new byte[16];
        System.arraycopy(decryptedKeys, 16, cmacBuf, 0, cmacBuf.length);

        // Position the buffer at the CMAC keys offset.
        byte[] inBuf = new byte[in.capacity() - 0x60 - headerOffset];
        System.arraycopy(in.array(), headerOffset + 0x60, inBuf, 0, inBuf.length);

        // Calculate CMAC header hash.
        aes.doInitCMAC(cmacBuf);
        aes.doUpdateCMAC(inBuf, 0, 0x30);
        cmacHeaderHash = aes.doFinalCMAC();

        int blockSize = header.dataSize;
        if ((blockSize % 16) != 0) {
            blockSize += (16 - (blockSize % 16));
        }

        // Calculate CMAC data hash.
        aes.doInitCMAC(cmacBuf);
        aes.doUpdateCMAC(inBuf, 0, 0x30 + blockSize + header.dataOffset);
        cmacDataHash = aes.doFinalCMAC();

        for (int i = 0; i < cmacHeaderHash.length; i++) {
        	if (cmacHeaderHash[i] != header.CMACHeaderHash[i]) {
        		return PSP_KIRK_INVALID_HEADER_HASH;
        	}
        }

        for (int i = 0; i < cmacDataHash.length; i++) {
        	if (cmacDataHash[i] != header.CMACDataHash[i]) {
        		return PSP_KIRK_INVALID_DATA_HASH;
        	}
        }

        return 0;
    }

    // Generate SHA1 hash.
    private int executeKIRKCmd11(ByteBuffer out, ByteBuffer in, int size) {
        // Return an error if the crypto engine hasn't been initialized.
        if (!CryptoEngine.getCryptoEngineStatus()) {
            return PSP_KIRK_NOT_INIT;
        }

        int outPosition = out.position();

        SHA1_Header header = new SHA1_Header(in);
        SHA1 sha1 = new SHA1();

        size = (size < header.dataSize) ? size : header.dataSize;
        header.readData(in, size);

        out.position(outPosition);
        out.put(sha1.doSHA1(header.data, size));
        in.clear();

        return 0;
    }

    // Generate ECDSA key pair.
    private int executeKIRKCmd12(ByteBuffer out, int size) {
        // Return an error if the crypto engine hasn't been initialized.
        if (!CryptoEngine.getCryptoEngineStatus()) {
            return PSP_KIRK_NOT_INIT;
        }

        if (size != 0x3C) {
            return PSP_KIRK_INVALID_SIZE;
        }

        // Start the ECDSA context.
        ECDSA ecdsa = new ECDSA();
        ECDSAKeygenCtx ctx = new ECDSAKeygenCtx(out);
        ecdsa.setCurve();

        // Generate the private/public key pair and write it back.
        ctx.private_key = ecdsa.getPrivateKey();
        ctx.public_key = new ECDSAPoint(ecdsa.getPublicKey());

        ctx.write();

        return 0;
    }

    // Multiply ECDSA point.
    private int executeKIRKCmd13(ByteBuffer out, int outSize, ByteBuffer in, int inSize) {
        // Return an error if the crypto engine hasn't been initialized.
        if (!CryptoEngine.getCryptoEngineStatus()) {
            return PSP_KIRK_NOT_INIT;
        }

        if ((inSize != 0x3C) || (outSize != 0x28)) {
        	// Accept inSize==0x3C and outSize==0x3C as this is sent by sceMemab_9BF0C95D from a real PSP
        	if (outSize != inSize) {
        		return PSP_KIRK_INVALID_SIZE;
        	}
        }

        // Start the ECDSA context.
        ECDSA ecdsa = new ECDSA();
        ECDSAMultiplyCtx ctx = new ECDSAMultiplyCtx(in, out);
        ecdsa.setCurve();

        // Multiply the public key.
        ecdsa.multiplyPublicKey(ctx.public_key.toByteArray(), ctx.multiplier);

        ctx.write();

        return 0;
    }

    // Generate pseudo random number.
    private int executeKIRKCmd14(ByteBuffer out, int size) {
        // Return an error if the crypto engine hasn't been initialized.
        if (!CryptoEngine.getCryptoEngineStatus()) {
            return PSP_KIRK_NOT_INIT;
        }

        // Set up a temporary buffer.
        byte[] temp = new byte[0x104];
        temp[0] = 0;
        temp[1] = 0;
        temp[2] = 1;
        temp[3] = 0;
        
        ByteBuffer bTemp = ByteBuffer.wrap(temp);
        
        // Random data to act as a key.
        byte[] key = {(byte) 0xA7, (byte) 0x2E, (byte) 0x4C, (byte) 0xB6, (byte) 0xC3,
            (byte) 0x34, (byte) 0xDF, (byte) 0x85, (byte) 0x70, (byte) 0x01, (byte) 0x49,
            (byte) 0xFC, (byte) 0xC0, (byte) 0x87, (byte) 0xC4, (byte) 0x77};

        // Direct call to get the system time.
        int systime = (int) System.currentTimeMillis();

        System.arraycopy(prng_data, 0, temp, 4, 0x14);
        temp[0x18] = (byte) (systime & 0xFF);
        temp[0x19] = (byte) ((systime >> 8) & 0xFF);
        temp[0x1A] = (byte) ((systime >> 16) & 0xFF);
        temp[0x1B] = (byte) ((systime >> 24) & 0xFF);

        System.arraycopy(key, 0, temp, 0x1C, 0x10);

        // Generate a SHA-1 for this PRNG context.
        ByteBuffer bPRNG = ByteBuffer.wrap(prng_data);
        executeKIRKCmd11(bPRNG, bTemp, 0x104);
        
        out.put(bPRNG.array());
        
        // Process the data recursively.
        for (int i = 0; i < size; i += 0x14) {
            int remaining = size % 0x14;
            int block = size / 0x14;

            if (block > 0) {
                out.put(bPRNG.array());
                executeKIRKCmd14(out, i);
            } else {
                if (remaining > 0) {
                    out.put(prng_data, out.position(), remaining);
                    i += remaining;
                }
            }
        }
        out.rewind();

        return 0;
    }

    // Sign data with ECDSA key pair.
    private int executeKIRKCmd16(ByteBuffer out, int outSize, ByteBuffer in, int inSize) {
        // Return an error if the crypto engine hasn't been initialized.
        if (!CryptoEngine.getCryptoEngineStatus()) {
            return PSP_KIRK_NOT_INIT;
        }

        if ((inSize != 0x34) || (outSize != 0x28)) {
            return PSP_KIRK_INVALID_SIZE;
        }

        // TODO
        ECDSA ecdsa = new ECDSA();
        ECDSASignCtx ctx = new ECDSASignCtx(in);
        ECDSASig sig = new ECDSASig();
        ecdsa.setCurve();

        return 0;
    }

    // Verify ECDSA signature.
    private int executeKIRKCmd17(ByteBuffer in, int size) {
        // Return an error if the crypto engine hasn't been initialized.
        if (!CryptoEngine.getCryptoEngineStatus()) {
            return PSP_KIRK_NOT_INIT;
        }

        if (size != 0x64) {
            return PSP_KIRK_INVALID_SIZE;
        }

        // TODO
        ECDSA ecdsa = new ECDSA();
        ECDSAVerifyCtx ctx = new ECDSAVerifyCtx(in);
        ecdsa.setCurve();

        return 0;
    }

    /*
     * HLE functions: high level implementation of crypto functions from
     * several modules which employ various algorithms and communicate with the
     * crypto engine in different ways.
     */

    /*
     * sceUtils - memlmd_01g.prx and memlmd_02g.prx
     */
    public void hleUtilsSetFuseID(int id0, int id1) {
        fuseID0 = id0;
        fuseID1 = id1;
    }

    public int hleUtilsBufferCopyWithRange(ByteBuffer out, int outsize, ByteBuffer in, int insize, int cmd) {
    	return hleUtilsBufferCopyWithRange(out, outsize, in, insize, insize, cmd);
    }

    public int hleUtilsBufferCopyWithRange(ByteBuffer out, int outsize, ByteBuffer in, int insizeAligned, int insize, int cmd) {
        switch (cmd) {
            case PSP_KIRK_CMD_DECRYPT_PRIVATE:
                return executeKIRKCmd1(out, in, insizeAligned);
            case PSP_KIRK_CMD_ENCRYPT:
                return executeKIRKCmd4(out, in, insizeAligned);
            case PSP_KIRK_CMD_ENCRYPT_FUSE:
                return executeKIRKCmd5(out, in, insizeAligned);
            case PSP_KIRK_CMD_DECRYPT:
                return executeKIRKCmd7(out, in, insizeAligned);
            case PSP_KIRK_CMD_DECRYPT_FUSE:
                return executeKIRKCmd8(out, in, insizeAligned);
            case PSP_KIRK_CMD_PRIV_SIG_CHECK:
                return executeKIRKCmd10(in, insizeAligned);
            case PSP_KIRK_CMD_SHA1_HASH:
                return executeKIRKCmd11(out, in, insizeAligned);
            case PSP_KIRK_CMD_ECDSA_GEN_KEYS:
                return executeKIRKCmd12(out, outsize);
            case PSP_KIRK_CMD_ECDSA_MULTIPLY_POINT:
                return executeKIRKCmd13(out, outsize, in, insize);
            case PSP_KIRK_CMD_PRNG:
                return executeKIRKCmd14(out, insizeAligned);
            case PSP_KIRK_CMD_ECDSA_SIGN:
                return executeKIRKCmd16(out, outsize, in, insize);
            case PSP_KIRK_CMD_ECDSA_VERIFY:
                return executeKIRKCmd17(in, insize);
            case PSP_KIRK_CMD_INIT:
            	return 0;
            case PSP_KIRK_CMD_CERT_VERIFY:
            	return 0;
            default:
                return PSP_KIRK_INVALID_OPERATION; // Dummy.
        }
    }
}
