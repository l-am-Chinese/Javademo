package JavaSmallProject;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;

public class AesCodec {

    int[] m_RoundNum = {10, 12, 14};
    int[] m_BlockCount = {4, 6, 8};
    int[][] m_SBox = {
            {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
            {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
            {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
            {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
            {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
            {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
            {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
            {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
            {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
            {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
            {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
            {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
            {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
            {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
            {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
            {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}

    };


    int[][] m_iSBox = {
            {0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb},
            {0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb},
            {0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e},
            {0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25},
            {0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92},
            {0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84},
            {0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06},
            {0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b},
            {0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73},
            {0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e},
            {0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b},
            {0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4},
            {0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f},
            {0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef},
            {0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61},
            {0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d}

    };


    int[][] m_Rcon = {
            {0x00, 0x00, 0x00, 0x00},
            {0x01, 0x00, 0x00, 0x00},
            {0x02, 0x00, 0x00, 0x00},
            {0x04, 0x00, 0x00, 0x00},
            {0x08, 0x00, 0x00, 0x00},
            {0x10, 0x00, 0x00, 0x00},
            {0x20, 0x00, 0x00, 0x00},
            {0x40, 0x00, 0x00, 0x00},
            {0x80, 0x00, 0x00, 0x00},
            {0x1b, 0x00, 0x00, 0x00},
            {0x36, 0x00, 0x00, 0x00}

    };


    public enum AES_CODE_BIT {

        AES_128BIT(0), AES_192BIT(1), AES_256BIT(2);

        private int value = 0;

        AES_CODE_BIT(int value) {

            this.value = value;

        }

    }



    private final int AES_BLOCK_PER_BYTES = 4;

    private final int AES_STATE_LEN = 16;



    private AES_CODE_BIT keyState = AES_CODE_BIT.AES_128BIT;

    private int nRound = 0;

    private int nKeyBlockLen = 0;

    private byte[] keyValue;

    private int[] keyExpansionValue;


    public AesCodec(AES_CODE_BIT keybit, byte[] key) {

        keyState = keybit;

        nRound = m_RoundNum[keyState.value];

        nKeyBlockLen = m_BlockCount[keyState.value];

        keyValue = key;

        keyExpansion();



    }


    private void addRoundKey(int[] pState, int round)
    {
        int Nb = AES_BLOCK_PER_BYTES;

        for (int r = 0; r < 4; ++r)
        {
            for (int c = 0; c < 4; ++c)
            {
                int tmp = pState[c * 4 + r];

                int rkey = keyExpansionValue[round * Nb * 4 + r * Nb + c];

                pState[c * 4 + r] = (tmp ^ rkey);

            }
        }
    }



    private void subBytes(int[] pState)     //行位移
    {
        for (int r = 0; r < 4; ++r)
        {
            for (int c = 0; c < 4; ++c)
            {
                int tmp = pState[r * 4 + c] & 0xff;

                pState[r * 4 + c] = m_SBox[((tmp >> 4) & 0x0F)][(tmp & 0x0F)];
            }
        }
    }


    private void inSubBytes(int[] pState)       //解行位移
    {
        for (int r = 0; r < 4; ++r)
        {
            for (int c = 0; c < 4; ++c)
            {
                int tmp = pState[r * 4 + c] & 0xff;

                pState[r * 4 + c] = m_iSBox[((tmp >> 4) & 0x0F)][(tmp & 0x0F)];
            }
        }
    }





    private void shiftRows(int[] pState)            //列混淆
    {
        int[] temp = new int[16];
        System.arraycopy(pState, 0, temp, 0, pState.length);

        int[][] rotate = {
                {1, 2, 3, 0},
                {2, 3, 0, 1},
                {3, 0, 1, 2}
        };

        for (int r = 1; r < 4; ++r) {
            for (int c = 0; c < 4; ++c)
            {
                pState[r * 4 + c] = temp[r * 4 + rotate[r - 1][c]];
            }
        }
    }



    private void inShiftRows(int[] pState)          //解列混淆
    {
        int[] temp = new int[16];

        System.arraycopy(pState, 0, temp, 0, pState.length);

        int[][] rotate = {
                {3, 0, 1, 2},
                {2, 3, 0, 1},
                {1, 2, 3, 0}
        };

        for (int r = 1; r < 4; ++r) {
            for (int c = 3; c >= 0; --c)
            {
                pState[r * 4 + c] = temp[r * 4 + rotate[r - 1][c]];
            }
        }
    }

    private void mixColumns(int[] pState)
    {
        int[] temp = new int[16];

        System.arraycopy(pState, 0, temp, 0, pState.length);

        for (int c = 0; c < 4; ++c)
        {
            int tmpVal0 = temp[0 * 4 + c];
            int tmpVal1 = temp[1 * 4 + c];
            int tmpVal2 = temp[2 * 4 + c];
            int tmpVal3 = temp[3 * 4 + c];

            pState[0 * 4 + c] = (GFMult02(tmpVal0)

                    ^ GFMult03(tmpVal1)

                    ^ GFMult01(tmpVal2)

                    ^ GFMult01(tmpVal3)) & 0xff;

            pState[1 * 4 + c] = (GFMult01(tmpVal0)

                    ^ GFMult02(tmpVal1)

                    ^ GFMult03(tmpVal2)

                    ^ GFMult01(tmpVal3)) & 0xff;

            pState[2 * 4 + c] = (GFMult01(tmpVal0)

                    ^ GFMult01(tmpVal1)

                    ^ GFMult02(tmpVal2)

                    ^ GFMult03(tmpVal3)) & 0xff;

            pState[3 * 4 + c] = (GFMult03(tmpVal0)

                    ^ GFMult01(tmpVal1)

                    ^ GFMult01(tmpVal2)

                    ^ GFMult02(tmpVal3)) & 0xff;

        }

    }



    private int xtime(int x) {

        x &= 0xff;

        return (((x) << 1) ^ ((((x) >> 7) & 1) * 0x1b));

    }



    private int GFMult01(int val){return val;}

    private int GFMult02(int val){return xtime(val);}

    private int GFMult03(int val){return xtime(val) ^ val;}

    private int GFMult09(int val){return GFMult02(GFMult02(GFMult02(val))) ^ GFMult01(val);}

    private int GFMult0B(int val){return GFMult09(val) ^ GFMult02(val);}

    private int GFMult0D(int val){return GFMult09(val) ^ GFMult02(GFMult02(val));}

    private int GFMult0E(int val){return GFMult02(GFMult02(GFMult02(val))) ^ GFMult02(GFMult02(val)) ^ GFMult02(val);}


    private void inMixColumns(int[] pState)
    {
        int[] temp = new int[16];

        System.arraycopy(pState, 0, temp, 0, pState.length);

        for (int c = 0; c < 4; ++c)
        {
            int tmpVal0 = temp[0 * 4 + c];

            int tmpVal1 = temp[1 * 4 + c];

            int tmpVal2 = temp[2 * 4 + c];

            int tmpVal3 = temp[3 * 4 + c];

            pState[0 * 4 + c] = (GFMult0E(tmpVal0)

                    ^ GFMult0B(tmpVal1)

                    ^ GFMult0D(tmpVal2)

                    ^ GFMult09(tmpVal3)) & 0xff;

            pState[1 * 4 + c] = (GFMult09(tmpVal0)

                    ^ GFMult0E(tmpVal1)

                    ^ GFMult0B(tmpVal2)

                    ^ GFMult0D(tmpVal3)) & 0xff;

            pState[2 * 4 + c] = (GFMult0D(tmpVal0)

                    ^ GFMult09(tmpVal1)

                    ^ GFMult0E(tmpVal2)

                    ^ GFMult0B(tmpVal3)) & 0xff;

            pState[3 * 4 + c] = (GFMult0B(tmpVal0)

                    ^ GFMult0D(tmpVal1)

                    ^ GFMult09(tmpVal2)

                    ^ GFMult0E(tmpVal3)) & 0xff;

        }

    }


    private void keyExpansion() {

        int size = (nRound + 1) * AES_BLOCK_PER_BYTES * 4;

        keyExpansionValue = new int[size];

        for (int row = 0; row < nKeyBlockLen; ++row) {

            keyExpansionValue[(row * 4) + 0] = keyValue[(row * 4)] & 0xff;

            keyExpansionValue[(row * 4) + 1] = keyValue[(row * 4) + 1] & 0xff;

            keyExpansionValue[(row * 4) + 2] = keyValue[(row * 4) + 2] & 0xff;

            keyExpansionValue[(row * 4) + 3] = keyValue[(row * 4) + 3] & 0xff;

        }

        int[] temp = new int[4];

        for (int row = nKeyBlockLen; row < AES_BLOCK_PER_BYTES * (nRound + 1); ++row) {

            temp[0] = keyExpansionValue[(row - 1) * 4 + 0];

            temp[1] = keyExpansionValue[(row - 1) * 4 + 1];

            temp[2] = keyExpansionValue[(row - 1) * 4 + 2];

            temp[3] = keyExpansionValue[(row - 1) * 4 + 3];

            if (row % nKeyBlockLen == 0) {

                rotWord(temp);

                subWord(temp);

                temp[0] = (temp[0] ^ m_Rcon[(row / nKeyBlockLen)][0]) & 0xff;

                temp[1] = (temp[1] ^ m_Rcon[(row / nKeyBlockLen)][1]) & 0xff;

                temp[2] = (temp[2] ^ m_Rcon[(row / nKeyBlockLen)][2]) & 0xff;

                temp[3] = (temp[3] ^ m_Rcon[(row / nKeyBlockLen)][3]) & 0xff;

            }
            else if (nKeyBlockLen > 6 && (row % nKeyBlockLen == 4)) {
                subWord(temp);
            }

            keyExpansionValue[(row * 4) + 0] = (keyExpansionValue[(row - nKeyBlockLen) * 4 + 0] ^ temp[0]) & 0xff;

            keyExpansionValue[(row * 4) + 1] = (keyExpansionValue[(row - nKeyBlockLen) * 4 + 1] ^ temp[1]) & 0xff;

            keyExpansionValue[(row * 4) + 2] = (keyExpansionValue[(row - nKeyBlockLen) * 4 + 2] ^ temp[2]) & 0xff;

            keyExpansionValue[(row * 4) + 3] = (keyExpansionValue[(row - nKeyBlockLen) * 4 + 3] ^ temp[3]) & 0xff;

        }

    }

    private void subWord(int[] pRow) {
        for (int i = 0;i  < 4; ++i) {

            int temp = pRow[i] & 0xff;

            pRow[i] = (int) m_SBox[((temp >> 4) & 0x0F)][(temp & 0x0F)];

        }
    }

    private void rotWord(int[] pRow) {
        int temp = pRow[0];

        pRow[0] = pRow[1];

        pRow[1] = pRow[2];

        pRow[2] = pRow[3];

        pRow[3] = temp;
    }


    private void encodeFlow(int[] pState) {         //轮加密

        addRoundKey(pState, 0);

        for (int round = 1; round <= (nRound - 1); ++round) {

            subBytes(pState);

            shiftRows(pState);

            mixColumns(pState);

            addRoundKey(pState, round);

        }

        subBytes(pState);

        shiftRows(pState);

        addRoundKey(pState, nRound);

    }

    private void decodeFlow(int[] pState) {     //轮解密

        addRoundKey(pState, nRound);

        for (int round = nRound - 1; round > 0; --round) {

            inShiftRows(pState);

            inSubBytes(pState);

            addRoundKey(pState, round);

            inMixColumns(pState);

        }

        inShiftRows(pState);

        inSubBytes(pState);

        addRoundKey(pState, 0);
    }


    public byte[] encode(byte[] pInput) {

        byte[] pOutput = new byte[(pInput.length + 16 - 1) / (16) * (16)];

        for (int i = 0; i < pInput.length; i += AES_STATE_LEN) {

            int leftLen = (pInput.length - i);

            int dataLen = leftLen > AES_STATE_LEN ? AES_STATE_LEN : leftLen;

            int[] state = new int[AES_STATE_LEN];

            for (int pos = 0; pos < dataLen; ++pos) {
                state[pos] = pInput[i + pos] & 0xff;
            }

            encodeFlow(state);

            for (int pos = 0; pos < state.length; ++pos) {
                pOutput[i + pos] = (byte)(state[pos] & 0xFF);
            }
        }

        return pOutput;

    }


    public byte[] decode(byte[] pInput) {

        byte[] pOutput = new byte[pInput.length];

        for (int i = 0; i < pInput.length; i += AES_STATE_LEN) {

            int leftLen = (pInput.length - i);

            int dataLen = leftLen > AES_STATE_LEN ? AES_STATE_LEN : leftLen;

            int[] state = new int[AES_STATE_LEN];

            for (int pos = 0; pos < dataLen; ++pos) {
                state[pos] = pInput[i + pos] & 0xff;
            }

            decodeFlow(state);

            for (int pos = 0; pos < dataLen; ++pos) {
                pOutput[i + pos] = (byte)(state[pos] & 0xFF);
            }
        }

        return pOutput;

    }

    private static final int ENC_LEN = 128;     //AES-128

    private static final byte[] ENCODED_END = {'z', 'h', 'a', 'n', 'g', 'h', 'a', 'o', 's', 'h', 'e', 'n', 'g', '1', '0', '6'};     //加密文件判断字符

    private static final byte[] DECODE_KEY = {'g', 'u', 'y', 'i', 'l', 'i', 'n', 'g', '1', '2', '3', '4', '5', '6', '7', '8'};      //密钥

    private static AesCodec aesCodec = new AesCodec(AES_CODE_BIT.AES_128BIT, DECODE_KEY);

    public static boolean isFileEncoded(final String absPath) throws IOException {      //检测是否加密

        if(absPath == null || absPath.equals("")) {
            return false;
        }

        if(!new File(absPath).exists()) {
            throw new FileNotFoundException();
        }

        RandomAccessFile accessFile = new RandomAccessFile(new File(absPath), "rw");

        int aLen = 16;

        byte[] endArr = new byte[aLen];

        accessFile.seek(accessFile.length() - ENCODED_END.length);

        int ret = accessFile.read(endArr, 0, endArr.length);

        accessFile.close();

        if(ret < 16) {
            return false;
        }

        String endStr = bytesToHex(endArr);

        for(int i=0; i<aLen; i++) {

            if(endArr[i] != ENCODED_END[i]) {
                return false;
            }

        }

        return true;

    }



    public static boolean encodeFile(final String absPath) throws IOException {     //加密

        if(absPath == null || absPath.equals("")) {
            return false;
        }

        if(!new File(absPath).exists()) {
            throw new FileNotFoundException();
        }

        RandomAccessFile accessFile = new RandomAccessFile(new File(absPath), "rw");

        byte[] headArr = new byte[ENC_LEN];

        accessFile.read(headArr, 0, headArr.length);

        long t1 = System.currentTimeMillis();

        byte[] encHead = aesCodec.encode(headArr);

        accessFile.seek(0);

        accessFile.write(encHead, 0, encHead.length);

        accessFile.seek(accessFile.length());

        accessFile.write(ENCODED_END, 0, ENCODED_END.length);

        String endStr = bytesToHex(ENCODED_END);

        accessFile.getFD().sync();

        accessFile.close();

        return true;

    }



    public static boolean decodeFile(final String absPath) throws IOException {     //解密

        if(absPath == null || absPath.equals("")) {
            return false;
        }

        if(!new File(absPath).exists()) {
            throw new FileNotFoundException();
        }

        RandomAccessFile accessFile = new RandomAccessFile(new File(absPath), "rw");

        byte[] headArr = new byte[ENC_LEN];

        accessFile.read(headArr, 0, headArr.length);

        byte[] decodeHead = aesCodec.decode(headArr);

        accessFile.seek(0);

        accessFile.write(decodeHead, 0, decodeHead.length);

        accessFile.setLength(accessFile.length() - ENCODED_END.length);

        accessFile.getFD().sync();

        accessFile.close();

        return true;

    }



    public static String bytesToHex(byte[] bytes) {                 //2进制->16进制

        final char[] hexArray = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

        char[] hexChars = new char[bytes.length * 2];

        int v;

        for (int j = 0; j < bytes.length; j++) {

            v = bytes[j] & 0xFF;

            hexChars[j * 2] = hexArray[v >>> 4];

            hexChars[j * 2 + 1] = hexArray[v & 0x0F];

        }

        return new String(hexChars);

    }

    public static void main(String[] args) {

        try {
            String filePath, fileName;

            fileName = "txt_file_1.txt";

            filePath = "123.txt";

            boolean ret1 = AesCodec.isFileEncoded(filePath);

            System.out.println("\n   1 ----------> is file" + fileName + " encoded ? " + ret1);

            if(AesCodec.isFileEncoded(filePath)) {

                AesCodec.decodeFile(filePath);

                ret1 = AesCodec.isFileEncoded(filePath);

                System.out.println("\n   2 ----------> is file" + fileName + " encoded ? " + ret1);

            }

            if(!AesCodec.isFileEncoded(filePath)) {

                AesCodec.encodeFile(filePath);

                ret1 = AesCodec.isFileEncoded(filePath);

                System.out.println("\n   3 ----------> is file" + fileName + " encoded ? " + ret1);

            }

        } catch(Exception e) {
            System.out.println("\n   ----------> Exception = " + e.toString());
        }

    }

}