/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package net.studioblueplanet.keepassdecrypt;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.*;


/**
 * Class containing the implementation of Argon2 function and its parameters.
 *
 * @author David Bertoldi
 * @see <a href="https://en.wikipedia.org/wiki/Argon2">Argon2</a>
 * @since 1.5.0
 */
public class Argon2Function
{
    public enum Argon2
    {
        /**
         * It maximizes resistance to GPU cracking attacks.
         * It accesses the memory array in a password dependent order, which reduces the possibility of time–memory trade-off (TMTO) attacks,
         * but introduces possible side-channel attacks
         */
        D,

        /**
         * It is optimized to resist side-channel attacks. It accesses the memory array in a password independent order.
         */
        I,

        /**
         * It is a hybrid version. It follows the Argon2i approach for the first half pass over memory and the Argon2d approach for subsequent passes.
         * It is recommended to use Argon2id except when there are reasons to prefer one of the other two modes.
         */
        ID;

    }    

    public static class BadParametersException extends Exception
    {

        private static final long serialVersionUID = 9204720180786210237L;

        /**
         * Constructs the exception.
         *
         * @param message the message describing the cause of the exception
         * @since 0.1.0
         */
        public BadParametersException(String message)
        {
            super(message);
        }

        /**
         * Constructs the exception.
         *
         * @param message   the message describing the cause of the exception
         * @param exception the exception masked by this object
         * @since 0.1.0
         */
        public BadParametersException(String message, Throwable exception)
        {
            super(message, exception);
        }
    }    
    
    private static class Blake2b
    {
        private static final long[] IV = { 0x6a09e667f3bcc908L, 0xbb67ae8584caa73bL, 0x3c6ef372fe94f82bL, 0xa54ff53a5f1d36f1L,
                0x510e527fade682d1L, 0x9b05688c2b3e6c1fL, 0x1f83d9abfb41bd6bL, 0x5be0cd19137e2179L };

        private static final byte[][] SIGMA = { { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
                { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 }, { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
                { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 }, { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
                { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 }, { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
                { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 }, { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
                { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 }, { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
                { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 } };

        private static final int ROUNDS = 12;

        private static final int BLOCK_LENGTH_BYTES = 128;

        private final int digestLength;

        private final int keyLength;

        private final byte[] buffer;

        private final long[] internalState = new long[16];

        private int bufferPos = 0;

        private long[] chainValue = null;

        private long t0 = 0L;

        private long t1 = 0L;

        private long f0 = 0L;

        /**
         * Basic sized constructor - size in bytes.
         *
         * @param digestSize size of the digest in bytes
         */
        Blake2b(int digestSize)
        {
            if (digestSize < 1 || digestSize > 64)
            {
                System.err.println("BLAKE2b digest bytes length must be not greater than 64");
            }

            buffer = new byte[BLOCK_LENGTH_BYTES];
            keyLength = 0;
            this.digestLength = digestSize;
            init();
        }

        // initialize chainValue
        private void init()
        {
            chainValue = new long[8];
            chainValue[0] = IV[0] ^ (digestLength | ((long) keyLength << 8) | 0x1010000);
            chainValue[1] = IV[1];
            chainValue[2] = IV[2];
            chainValue[3] = IV[3];
            chainValue[4] = IV[4];
            chainValue[5] = IV[5];
            chainValue[6] = IV[6];
            chainValue[7] = IV[7];
        }

        private void initializeInternalState()
        {
            System.arraycopy(chainValue, 0, internalState, 0, chainValue.length);
            System.arraycopy(IV, 0, internalState, chainValue.length, 4);
            internalState[12] = t0 ^ IV[4];
            internalState[13] = t1 ^ IV[5];
            internalState[14] = f0 ^ IV[6];
            internalState[15] = IV[7];// ^ f1 with f1 = 0
        }

        void update(byte[] message)
        {
            if (message == null)
            {
                return;
            }
            update(message, 0, message.length);
        }

        /**
         * update the message digest with a block of bytes.
         *
         * @param message the byte array containing the data.
         * @param offset  the offset into the byte array where the data starts.
         * @param len     the length of the data.
         */
        void update(byte[] message, int offset, int len)
        {
            int remainingLength = 0;

            if (bufferPos != 0)
            {
                remainingLength = BLOCK_LENGTH_BYTES - bufferPos;
                if (remainingLength < len)
                {
                    System.arraycopy(message, offset, buffer, bufferPos, remainingLength);
                    t0 += BLOCK_LENGTH_BYTES;
                    if (t0 == 0)
                    {
                        t1++;
                    }
                    compress(buffer, 0);
                    bufferPos = 0;
                    Arrays.fill(buffer, (byte) 0);// clear buffer
                }
                else
                {
                    System.arraycopy(message, offset, buffer, bufferPos, len);
                    bufferPos += len;
                    return;
                }
            }

            int messagePos;
            int blockWiseLastPos = offset + len - BLOCK_LENGTH_BYTES;
            for (messagePos = offset + remainingLength; messagePos < blockWiseLastPos; messagePos += BLOCK_LENGTH_BYTES)
            {
                t0 += BLOCK_LENGTH_BYTES;
                if (t0 == 0)
                {
                    t1++;
                }
                compress(message, messagePos);
            }

            // fill the buffer with left bytes, this might be a full block
            System.arraycopy(message, messagePos, buffer, 0, offset + len - messagePos);
            bufferPos += offset + len - messagePos;
        }

        /**
         * close the digest, producing the final digest value. The doFinal
         * call leaves the digest reset.
         * Key, salt and personal string remain.
         *
         * @param out       the array the digest is to be copied into.
         * @param outOffset the offset into the out array the digest is to start at.
         */
        void doFinal(byte[] out, int outOffset)
        {

            f0 = 0xFFFFFFFFFFFFFFFFL;
            t0 += bufferPos;
            if (bufferPos > 0 && t0 == 0)
            {
                t1++;
            }
            compress(buffer, 0);
            Arrays.fill(buffer, (byte) 0);// Holds eventually the key if input is null
            Arrays.fill(internalState, 0L);

            for (int i = 0; i < chainValue.length && (i * 8 < digestLength); i++)
            {
                byte[] bytes = longToLittleEndian(chainValue[i]);

                if (i * 8 < digestLength - 8)
                {
                    System.arraycopy(bytes, 0, out, outOffset + i * 8, 8);
                }
                else
                {
                    System.arraycopy(bytes, 0, out, outOffset + i * 8, digestLength - (i * 8));
                }
            }

            Arrays.fill(chainValue, 0L);

            reset();
        }

        /**
         * Reset the digest back to it's initial state.
         * The key, the salt and the personal string will
         * remain for further computations.
         */
        void reset()
        {
            bufferPos = 0;
            f0 = 0L;
            t0 = 0L;
            t1 = 0L;
            chainValue = null;
            Arrays.fill(buffer, (byte) 0);
            init();
        }

        private static int littleEndianToInt(byte[] bs, int off)
        {
            int n = bs[off] & 0xff;
            n |= (bs[++off] & 0xff) << 8;
            n |= (bs[++off] & 0xff) << 16;
            n |= bs[++off] << 24;
            return n;
        }


        private static long littleEndianToLong(byte[] bs, int off)
        {
            int lo = littleEndianToInt(bs, off);
            int hi = littleEndianToInt(bs, off + 4);
            return ((hi & 0xffffffffL) << 32) | (lo & 0xffffffffL);
        }        
        
        private void compress(byte[] message, int messagePos)
        {

            initializeInternalState();

            long[] m = new long[16];
            for (int j = 0; j < 16; j++)
            {
                m[j] = littleEndianToLong(message, messagePos + j * 8);
            }

            for (int round = 0; round < ROUNDS; round++)
            {

                // G apply to columns of internalState:m[blake2b_sigma[round][2 *
                // blockPos]] /+1
                functionG(m[SIGMA[round][0]], m[SIGMA[round][1]], 0, 4, 8, 12);
                functionG(m[SIGMA[round][2]], m[SIGMA[round][3]], 1, 5, 9, 13);
                functionG(m[SIGMA[round][4]], m[SIGMA[round][5]], 2, 6, 10, 14);
                functionG(m[SIGMA[round][6]], m[SIGMA[round][7]], 3, 7, 11, 15);
                // G apply to diagonals of internalState:
                functionG(m[SIGMA[round][8]], m[SIGMA[round][9]], 0, 5, 10, 15);
                functionG(m[SIGMA[round][10]], m[SIGMA[round][11]], 1, 6, 11, 12);
                functionG(m[SIGMA[round][12]], m[SIGMA[round][13]], 2, 7, 8, 13);
                functionG(m[SIGMA[round][14]], m[SIGMA[round][15]], 3, 4, 9, 14);
            }

            // update chain values:
            for (int offset = 0; offset < chainValue.length; offset++)
            {
                chainValue[offset] = chainValue[offset] ^ internalState[offset] ^ internalState[offset + 8];
            }
        }

        private void functionG(long m1, long m2, int posA, int posB, int posC, int posD)
        {

            internalState[posA] = internalState[posA] + internalState[posB] + m1;
            internalState[posD] = Long.rotateRight(internalState[posD] ^ internalState[posA], 32);
            internalState[posC] = internalState[posC] + internalState[posD];
            internalState[posB] = Long.rotateRight(internalState[posB] ^ internalState[posC], 24); // replaces 25 of BLAKE
            internalState[posA] = internalState[posA] + internalState[posB] + m2;
            internalState[posD] = Long.rotateRight(internalState[posD] ^ internalState[posA], 16);
            internalState[posC] = internalState[posC] + internalState[posD];
            internalState[posB] = Long.rotateRight(internalState[posB] ^ internalState[posC], 63); // replaces 11 of BLAKE
        }
    }    

    public static final int ARGON2_VERSION_10 = 0x10;

    public static final int ARGON2_VERSION_13 = 0x13;

    public static final int ARGON2_INITIAL_DIGEST_LENGTH = 64;

    public static final int ARGON2_ADDRESSES_IN_BLOCK = 128;

    private static final ConcurrentMap<String, Argon2Function> INSTANCES = new ConcurrentHashMap<>();

    private static final int ARGON2_SYNC_POINTS = 4;

    private static final int ARGON2_INITIAL_SEED_LENGTH = 72;

    private static final int ARGON2_BLOCK_SIZE = 1024;

    public static final int ARGON2_QWORDS_IN_BLOCK = ARGON2_BLOCK_SIZE / 8;

    private final int iterations;

    private final int memory;

    private final long[][] initialBlockMemory;

    private final int parallelism;

    private final int outputLength;

    private final int segmentLength;

    private final Argon2 variant;

    private final int version;

    private final int laneLength;

    private Argon2Function(int memory, int iterations, int parallelism, int outputLength, Argon2 variant, int version)
    {
        this.variant = variant;
        this.iterations = iterations;
        this.memory = memory;
        this.parallelism = parallelism;
        this.outputLength = outputLength;
        this.version = version;

        int memoryBlocks = this.memory;

        if (this.memory < 2 * ARGON2_SYNC_POINTS * parallelism)
        {
            memoryBlocks = 2 * ARGON2_SYNC_POINTS * parallelism;
        }

        segmentLength = memoryBlocks / (parallelism * ARGON2_SYNC_POINTS);
        this.laneLength = segmentLength * ARGON2_SYNC_POINTS;

        memoryBlocks = segmentLength * (parallelism * ARGON2_SYNC_POINTS);

        initialBlockMemory = new long[memoryBlocks][ARGON2_QWORDS_IN_BLOCK];
        for (int i = 0; i < memoryBlocks; i++)
        {
            initialBlockMemory[i] = new long[ARGON2_QWORDS_IN_BLOCK];
        }
    }

    /**
     * Creates a singleton instance, depending on the provided
     * memory (KiB), number of iterations, parallelism, length og the output and type.
     *
     * @param memory       memory (KiB)
     * @param iterations   number of iterations
     * @param parallelism  level of parallelism
     * @param outputLength length of the final hash
     * @param type         argon2 type (i, d or id)
     * @return a singleton instance
     * @since 1.5.0
     */
    public static Argon2Function getInstance(int memory, int iterations, int parallelism, int outputLength, Argon2 type)
    {
        return getInstance(memory, iterations, parallelism, outputLength, type, ARGON2_VERSION_13);
    }

    /**
     * Creates a singleton instance, depending on the provided
     * logarithmic memory, number of iterations, parallelism, lenght og the output, type and version.
     *
     * @param memory       logarithmic memory
     * @param iterations   number of iterations
     * @param parallelism  level of parallelism
     * @param outputLength length of the final hash
     * @param type         argon2 type (i, d or id)
     * @param version      version of the algorithm (16 or 19)
     * @return a singleton instance
     * @since 1.5.0
     */
    public static Argon2Function getInstance(int memory, int iterations, int parallelism, int outputLength, Argon2 type,
            int version)
    {
        String key = getUID(memory, iterations, parallelism, outputLength, type, version);
        if (INSTANCES.containsKey(key))
        {
            return INSTANCES.get(key);
        }
        else
        {
            Argon2Function function = new Argon2Function(memory, iterations, parallelism, outputLength, type, version);
            INSTANCES.put(key, function);
            return function;
        }
    }

    // UTILS
    
    private static void xor(long[] t, long[] b1, long[] b2)
    {
        for (int i = 0; i < t.length; i++)
        {
            t[i] = b1[i] ^ b2[i];
        }
    }

    private static void xor(long[] t, long[] b1, long[] b2, long[] b3)
    {
        for (int i = 0; i < t.length; i++)
        {
            t[i] = b1[i] ^ b2[i] ^ b3[i];
        }
    }

    private static void xor(long[] t, long[] other)
    {
        for (int i = 0; i < t.length; i++)
        {
            t[i] = t[i] ^ other[i];
        }
    }    

    private static long littleEndianBytesToLong(byte[] b)
    {
        long result = 0;
        for (int i = 7; i >= 0; i--)
        {
            result <<= 8;
            result |= (b[i] & 0xFF);
        }
        return result;
    }    
    
    private static long intToLong(int x)
    {
        byte[] intBytes = intToLittleEndianBytes(x);
        byte[] bytes = new byte[8];
        System.arraycopy(intBytes, 0, bytes, 0, 4);
        return littleEndianBytesToLong(bytes);
    }    
    private static byte[] longToLittleEndianBytes(long a)
    {
        byte[] result = new byte[8];
        result[0] = (byte) (a & 0xFF);
        result[1] = (byte) ((a >> 8) & 0xFF);
        result[2] = (byte) ((a >> 16) & 0xFF);
        result[3] = (byte) ((a >> 24) & 0xFF);
        result[4] = (byte) ((a >> 32) & 0xFF);
        result[5] = (byte) ((a >> 40) & 0xFF);
        result[6] = (byte) ((a >> 48) & 0xFF);
        result[7] = (byte) ((a >> 56) & 0xFF);
        return result;
    }    
    
    private static byte[] intToLittleEndianBytes(int a)
    {
        byte[] result = new byte[4];
        result[0] = (byte) (a & 0xFF);
        result[1] = (byte) ((a >> 8) & 0xFF);
        result[2] = (byte) ((a >> 16) & 0xFF);
        result[3] = (byte) ((a >> 24) & 0xFF);
        return result;
    }

    static byte[] longToLittleEndian(long n)
    {
        byte[] bs = new byte[8];
        longToLittleEndian(n, bs, 0);
        return bs;
    }

    static void intToLittleEndian(int n, byte[] bs, int off)
    {
        bs[off] = (byte) (n);
        bs[++off] = (byte) (n >>> 8);
        bs[++off] = (byte) (n >>> 16);
        bs[++off] = (byte) (n >>> 24);
    }
    
    private static void longToLittleEndian(long n, byte[] bs, int off)
    {
        intToLittleEndian((int) (n & 0xffffffffL), bs, off);
        intToLittleEndian((int) (n >>> 32), bs, off + 4);
    }    
    
    private static long[] fromBytesToLongs(byte[] input)
    {
        long[] v = new long[128];
        for (int i = 0; i < v.length; i++)
        {
            byte[] slice = Arrays.copyOfRange(input, i * 8, (i + 1) * 8);
            v[i] = littleEndianBytesToLong(slice);
        }
        return v;
    }
    // END UTILS


    
    protected static String getUID(int memory, int iterations, int parallelism, int outputLength, Argon2 type, int version)
    {
        return memory + "|" + iterations + "|" + parallelism + "|" + outputLength + "|" + type.ordinal() + "|" + version;
    }

    private static byte[] getInitialHashLong(byte[] initialHash, byte[] appendix)
    {
        byte[] initialHashLong = new byte[ARGON2_INITIAL_SEED_LENGTH];

        System.arraycopy(initialHash, 0, initialHashLong, 0, ARGON2_INITIAL_DIGEST_LENGTH);
        System.arraycopy(appendix, 0, initialHashLong, ARGON2_INITIAL_DIGEST_LENGTH, 4);

        return initialHashLong;
    }

    private static void updateWithLength(Blake2b blake2b, byte[] input)
    {
        if (input != null)
        {
            blake2b.update(intToLittleEndianBytes(input.length));
            blake2b.update(input);
        }
        else
        {
            blake2b.update(intToLittleEndianBytes(0));
        }
    }

    private static int getStartingIndex(int pass, int slice)
    {
        if ((pass == 0) && (slice == 0))
        {
            return 2;
        }
        else
        {
            return 0;
        }
    }

    private static void nextAddresses(long[] zeroBlock, long[] inputBlock, long[] addressBlock)
    {
        inputBlock[6]++;
        fillBlock(zeroBlock, inputBlock, addressBlock, false);
        fillBlock(zeroBlock, addressBlock, addressBlock, false);
    }

    private static void fillBlock(long[] x, long[] y, long[] currentBlock, boolean withXor)
    {

        long[] r = new long[ARGON2_QWORDS_IN_BLOCK];
        long[] z = new long[ARGON2_QWORDS_IN_BLOCK];

        xor(r, x, y);
        System.arraycopy(r, 0, z, 0, z.length);

        for (int i = 0; i < 8; i++)
        {

            roundFunction(z, 16 * i, 16 * i + 1, 16 * i + 2, 16 * i + 3, 16 * i + 4, 16 * i + 5, 16 * i + 6, 16 * i + 7,
                    16 * i + 8, 16 * i + 9, 16 * i + 10, 16 * i + 11, 16 * i + 12, 16 * i + 13, 16 * i + 14, 16 * i + 15);
        }

        for (int i = 0; i < 8; i++)
        {

            roundFunction(z, 2 * i, 2 * i + 1, 2 * i + 16, 2 * i + 17, 2 * i + 32, 2 * i + 33, 2 * i + 48, 2 * i + 49, 2 * i + 64,
                    2 * i + 65, 2 * i + 80, 2 * i + 81, 2 * i + 96, 2 * i + 97, 2 * i + 112, 2 * i + 113);

        }

        if (withXor)
        {
            xor(currentBlock, r, z, currentBlock);
        }
        else
        {
            xor(currentBlock, r, z);
        }
    }

    private static void roundFunction(long[] block, int v0, int v1, int v2, int v3, int v4, int v5, int v6, int v7, int v8,
            int v9, // NOSONAR
            int v10, int v11, int v12, int v13, int v14, int v15)
    {
        f(block, v0, v4, v8, v12);
        f(block, v1, v5, v9, v13);
        f(block, v2, v6, v10, v14);
        f(block, v3, v7, v11, v15);

        f(block, v0, v5, v10, v15);
        f(block, v1, v6, v11, v12);
        f(block, v2, v7, v8, v13);
        f(block, v3, v4, v9, v14);
    }

    private static void f(long[] block, int a, int b, int c, int d)
    {
        fBlaMka(block, a, b);
        rotr64(block, d, a, 32);

        fBlaMka(block, c, d);
        rotr64(block, b, c, 24);

        fBlaMka(block, a, b);
        rotr64(block, d, a, 16);

        fBlaMka(block, c, d);
        rotr64(block, b, c, 63);
    }

    private static void fBlaMka(long[] block, int x, int y)
    {
        final long m = 0xFFFFFFFFL;
        final long xy = (block[x] & m) * (block[y] & m);

        block[x] = block[x] + block[y] + 2 * xy;
    }

    private static void rotr64(long[] block, int v, int w, long c)
    {
        final long temp = block[v] ^ block[w];
        block[v] = (temp >>> c) | (temp << (64 - c));
    }



    protected static String toString(int memory, int iterations, int parallelism, int outputLength, Argon2 type, int version)
    {
        return "m=" + memory + ", i=" + iterations + ", p=" + parallelism + ", l=" + outputLength + ", t=" + type
                .name() + ", v=" + version;
    }


    public byte[] hash(byte[] plainTextPassword, byte[] salt)
    {
        return hash(plainTextPassword, salt, null);
    }

    public byte[] hash(byte[] plainTextPassword, byte[] salt, byte[] pepper)
    {
        return internalHash(plainTextPassword, salt, pepper);
    }

    private byte[] internalHash(byte[] plainTextPassword, byte[] salt, byte[] pepper)
    {
        long[][] blockMemory = copyOf(initialBlockMemory);

        if (salt == null)
        {
//            salt = SaltGenerator.generate();
        }
        initialize(plainTextPassword, salt, pepper, null, blockMemory);
        fillMemoryBlocks(blockMemory);
        byte[] hash = ending(blockMemory);
        return hash;
    }
    
    /**
     * @return the memory in bytes
     * @since 1.5.2
     */
    public int getMemory()
    {
        return memory;
    }

    /**
     * @return the number of iterations
     * @since 1.5.2
     */
    public int getIterations()
    {
        return iterations;
    }

    /**
     * @return the degree of parallelism
     * @since 1.5.2
     */
    public int getParallelism()
    {
        return parallelism;
    }

    /**
     * @return the length of the produced hash
     * @since 1.5.2
     */
    public int getOutputLength()
    {
        return outputLength;
    }

    /**
     * @return the Argon2 variant (i, d, id)
     * @since 1.5.2
     */
    public Argon2 getVariant()
    {
        return variant;
    }

    /**
     * @return the version of the algorithm
     * @since 1.5.2
     */
    public int getVersion()
    {
        return version;
    }

    private void initialize(byte[] plainTextPassword, byte[] salt, byte[] secret, byte[] additional, long[][] blockMemory)
    {
        Blake2b blake2b = new Blake2b(ARGON2_INITIAL_DIGEST_LENGTH);

        blake2b.update(intToLittleEndianBytes(parallelism));
        blake2b.update(intToLittleEndianBytes(outputLength));
        blake2b.update(intToLittleEndianBytes(memory));
        blake2b.update(intToLittleEndianBytes(iterations));
        blake2b.update(intToLittleEndianBytes(version));
        blake2b.update(intToLittleEndianBytes(variant.ordinal()));

        updateWithLength(blake2b, plainTextPassword);

        updateWithLength(blake2b, salt);

        updateWithLength(blake2b, secret);

        updateWithLength(blake2b, additional);

        byte[] initialHash = new byte[64];
        blake2b.doFinal(initialHash, 0);

        final byte[] zeroBytes = { 0, 0, 0, 0 };
        final byte[] oneBytes = { 1, 0, 0, 0 };

        byte[] initialHashWithZeros = getInitialHashLong(initialHash, zeroBytes);
        byte[] initialHashWithOnes = getInitialHashLong(initialHash, oneBytes);

        for (int i = 0; i < parallelism; i++)
        {

            byte[] iBytes = intToLittleEndianBytes(i);

            System.arraycopy(iBytes, 0, initialHashWithZeros, ARGON2_INITIAL_DIGEST_LENGTH + 4, 4);
            System.arraycopy(iBytes, 0, initialHashWithOnes, ARGON2_INITIAL_DIGEST_LENGTH + 4, 4);

            byte[] blockHashBytes = blake2bLong(initialHashWithZeros, ARGON2_BLOCK_SIZE);
            blockMemory[i * laneLength] = fromBytesToLongs(blockHashBytes);

            blockHashBytes = blake2bLong(initialHashWithOnes, ARGON2_BLOCK_SIZE);
            blockMemory[i * laneLength + 1] = fromBytesToLongs(blockHashBytes);
        }

    }

    private byte[] blake2bLong(byte[] input, int outputLength)
    {

        byte[] result = new byte[outputLength];
        byte[] outlenBytes = intToLittleEndianBytes(outputLength);

        int blake2bLength = 64;

        if (outputLength <= blake2bLength)
        {
            result = simpleBlake2b(input, outlenBytes, outputLength);
        }
        else
        {
            byte[] outBuffer;

            outBuffer = simpleBlake2b(input, outlenBytes, blake2bLength);
            System.arraycopy(outBuffer, 0, result, 0, blake2bLength / 2);

            int r = (outputLength / 32) + (outputLength % 32 == 0 ? 0 : 1) - 2;

            int position = blake2bLength / 2;
            for (int i = 2; i <= r; i++, position += blake2bLength / 2)
            {

                outBuffer = simpleBlake2b(outBuffer, null, blake2bLength);
                System.arraycopy(outBuffer, 0, result, position, blake2bLength / 2);
            }

            int lastLength = outputLength - 32 * r;

            outBuffer = simpleBlake2b(outBuffer, null, lastLength);
            System.arraycopy(outBuffer, 0, result, position, lastLength);
        }

        return result;
    }

    private byte[] simpleBlake2b(byte[] input, byte[] outlenBytes, int outputLength)
    {
        Blake2b blake2b = new Blake2b(outputLength);

        if (outlenBytes != null)
            blake2b.update(outlenBytes);
        blake2b.update(input);

        byte[] buff = new byte[outputLength];
        blake2b.doFinal(buff, 0);
        return buff;
    }

    private void fillMemoryBlocks(long[][] blockMemory)
    {
        if (parallelism == 1)
        {
            fillMemoryBlockSingleThreaded(blockMemory);
        }
        else
        {
            fillMemoryBlockMultiThreaded(blockMemory);
        }
    }

    private void fillMemoryBlockSingleThreaded(long[][] blockMemory)
    {
        for (int pass = 0; pass < iterations; pass++)
        {
            for (int slice = 0; slice < ARGON2_SYNC_POINTS; slice++)
            {
                fillSegment(pass, 0, slice, blockMemory);
            }
        }
    }

    private void fillMemoryBlockMultiThreaded(long[][] blockMemory)
    {

        ExecutorService service = Executors.newFixedThreadPool(parallelism);
        List<Future<?>> futures = new ArrayList<>();

        for (int i = 0; i < iterations; i++)
        {
            for (int j = 0; j < ARGON2_SYNC_POINTS; j++)
            {
                for (int k = 0; k < parallelism; k++)
                {
                    int pass = i;
                    int lane = k;
                    int slice = j;

                    Future<?> future = service.submit(() -> fillSegment(pass, lane, slice, blockMemory));

                    futures.add(future);
                }

                try
                {
                    for (Future<?> f : futures)
                    {
                        f.get();
                    }
                }
                catch (InterruptedException | ExecutionException e)
                {
                    clear(blockMemory);
                    Thread.currentThread().interrupt();
                }
            }
        }

        service.shutdownNow();
    }

    private void fillSegment(int pass, int lane, int slice, long[][] blockMemory)
    {

        long[] addressBlock = null;
        long[] inputBlock = null;
        long[] zeroBlock = null;

        boolean dataIndependentAddressing = isDataIndependentAddressing(pass, slice);
        int startingIndex = getStartingIndex(pass, slice);
        int currentOffset = lane * laneLength + slice * segmentLength + startingIndex;
        int prevOffset = getPrevOffset(currentOffset);

        if (dataIndependentAddressing)
        {
            addressBlock = new long[ARGON2_QWORDS_IN_BLOCK];
            zeroBlock = new long[ARGON2_QWORDS_IN_BLOCK];
            inputBlock = new long[ARGON2_QWORDS_IN_BLOCK];

            initAddressBlocks(pass, lane, slice, zeroBlock, inputBlock, addressBlock, blockMemory);
        }

        for (int i = startingIndex; i < segmentLength; i++, currentOffset++, prevOffset++)
        {
            prevOffset = rotatePrevOffset(currentOffset, prevOffset);

            long pseudoRandom = getPseudoRandom(i, addressBlock, inputBlock, zeroBlock, prevOffset, dataIndependentAddressing,
                    blockMemory);
            int refLane = getRefLane(pass, lane, slice, pseudoRandom);
            int refColumn = getRefColumn(pass, slice, i, pseudoRandom, refLane == lane);

            long[] prevBlock = blockMemory[prevOffset];
            long[] refBlock = blockMemory[((laneLength) * refLane + refColumn)];
            long[] currentBlock = blockMemory[currentOffset];

            boolean withXor = isWithXor(pass);
            fillBlock(prevBlock, refBlock, currentBlock, withXor);
        }
    }

    private boolean isDataIndependentAddressing(int pass, int slice)
    {
        return (variant == Argon2.I) || (variant == Argon2.ID && (pass == 0) && (slice < ARGON2_SYNC_POINTS / 2));
    }

    private int getPrevOffset(int currentOffset)
    {
        if (currentOffset % laneLength == 0)
        {

            return currentOffset + laneLength - 1;
        }
        else
        {

            return currentOffset - 1;
        }
    }

    private int rotatePrevOffset(int currentOffset, int prevOffset)
    {
        if (currentOffset % laneLength == 1)
        {
            prevOffset = currentOffset - 1;
        }
        return prevOffset;
    }

    private long getPseudoRandom(int index, long[] addressBlock, long[] inputBlock, long[] zeroBlock, int prevOffset,
            boolean dataIndependentAddressing, long[][] blockMemory)
    {
        if (dataIndependentAddressing)
        {
            if (index % ARGON2_ADDRESSES_IN_BLOCK == 0)
            {
                nextAddresses(zeroBlock, inputBlock, addressBlock);
            }
            return addressBlock[index % ARGON2_ADDRESSES_IN_BLOCK];
        }
        else
        {
            return blockMemory[prevOffset][0];
        }
    }

    private int getRefLane(int pass, int lane, int slice, long pseudoRandom)
    {
        int refLane = (int) ((pseudoRandom >>> 32) % parallelism);

        if (pass == 0 && slice == 0)
        {
            refLane = lane;
        }
        return refLane;
    }

    private void initAddressBlocks(int pass, int lane, int slice, long[] zeroBlock, long[] inputBlock, long[] addressBlock,
            long[][] blockMemory)
    {
        inputBlock[0] = intToLong(pass);
        inputBlock[1] = intToLong(lane);
        inputBlock[2] = intToLong(slice);
        inputBlock[3] = intToLong(blockMemory.length);
        inputBlock[4] = intToLong(iterations);
        inputBlock[5] = intToLong(variant.ordinal());

        if (pass == 0 && slice == 0)
        {

            nextAddresses(zeroBlock, inputBlock, addressBlock);
        }
    }

    private int getRefColumn(int pass, int slice, int index, long pseudoRandom, boolean sameLane)
    {

        int referenceAreaSize;
        int startPosition;

        if (pass == 0)
        {
            startPosition = 0;

            if (sameLane)
            {
                referenceAreaSize = slice * segmentLength + index - 1;
            }
            else
            {
                referenceAreaSize = slice * segmentLength + ((index == 0) ? (-1) : 0);
            }

        }
        else
        {
            startPosition = ((slice + 1) * segmentLength) % laneLength;

            if (sameLane)
            {
                referenceAreaSize = laneLength - segmentLength + index - 1;
            }
            else
            {
                referenceAreaSize = laneLength - segmentLength + ((index == 0) ? (-1) : 0);
            }
        }

        long relativePosition = pseudoRandom & 0xFFFFFFFFL;

        relativePosition = (relativePosition * relativePosition) >>> 32;
        relativePosition = referenceAreaSize - 1 - (referenceAreaSize * relativePosition >>> 32);

        return (int) (startPosition + relativePosition) % laneLength;
    }

    private boolean isWithXor(int pass)
    {
        return !(pass == 0 || version == ARGON2_VERSION_10);
    }

    private byte[] ending(long[][] blockMemory)
    {

        long[] finalBlock = blockMemory[laneLength - 1];

        for (int i = 1; i < parallelism; i++)
        {
            int lastBlockInLane = i * laneLength + (laneLength - 1);
            xor(finalBlock, blockMemory[lastBlockInLane]);
        }

        byte[] finalBlockBytes = new byte[ARGON2_BLOCK_SIZE];

        for (int i = 0; i < finalBlock.length; i++)
        {
            byte[] bytes = longToLittleEndianBytes(finalBlock[i]);
            System.arraycopy(bytes, 0, finalBlockBytes, i * bytes.length, bytes.length);
        }

        byte[] finalResult = blake2bLong(finalBlockBytes, outputLength);

        clear(blockMemory);

        return finalResult;
    }

    private void clear(long[][] blockMemory)
    {
        for (long[] block : blockMemory)
        {
            Arrays.fill(block, 0);
        }
    }

    private long[][] copyOf(long[][] old)
    {
        long[][] current = new long[old.length][ARGON2_QWORDS_IN_BLOCK];
        for (int i = 0; i < old.length; i++)
        {
            System.arraycopy(current[i], 0, old[i], 0, ARGON2_QWORDS_IN_BLOCK);
        }
        return current;
    }

    private static String remove(String source, String remove)
    {
        return source.substring(remove.length());
    }

    @Override
    public boolean equals(Object o)
    {
        if (this == o)
            return true;
        if (!(o instanceof Argon2Function))
            return false;
        Argon2Function other = (Argon2Function) o;
        return iterations == other.iterations //
                && memory == other.memory //
                && parallelism == other.parallelism //
                && outputLength == other.outputLength //
                && version == other.version //
                && variant == other.variant;
    }

    @Override
    public int hashCode()
    {
        return Objects.hash(iterations, memory, parallelism, outputLength, variant, version);
    }

    @Override
    public String toString()
    {
        return getClass().getSimpleName() + '[' + toString(memory, iterations, parallelism, outputLength, variant, version) + ']';
    }
}