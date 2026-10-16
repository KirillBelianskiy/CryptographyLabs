using Package01.Abstractions;

namespace Package01.Feistel;

public sealed class FeistelNetwork : ISymmetricBlockCipher
{
    private readonly IKeyExpansion _keyExpansion;
    private readonly IRoundTransformation _roundTransformation;
    private byte[][]? _roundKeys;

    public int BlockSizeBytes { get; }

    public FeistelNetwork(
        IKeyExpansion keyExpansion,
        IRoundTransformation roundTransformation,
        int blockSizeBytes = 8)
    {
        _keyExpansion = keyExpansion ??
            throw new ArgumentNullException(nameof(keyExpansion), "Key expansion cannot be null.");
        _roundTransformation = roundTransformation ??
            throw new ArgumentNullException(nameof(roundTransformation), "Round transformation cannot be null.");

        if (blockSizeBytes <= 0 || blockSizeBytes % 2 != 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(blockSizeBytes),
                "Block size must be positive and even.");
        }

        BlockSizeBytes = blockSizeBytes;
    }

    public void SetKey(byte[] key)
    {
        if (key is null)
        {
            throw new ArgumentNullException(nameof(key), "Key cannot be null.");
        }

        if (key.Length == 0)
        {
            throw new ArgumentException("Key cannot be empty.", nameof(key));
        }

        byte[][] expanded = _keyExpansion.ExpandKey((byte[])key.Clone());
        if (expanded is null || expanded.Length == 0)
        {
            throw new InvalidOperationException("Key expansion must return at least one round key.");
        }

        byte[][] snapshot = new byte[expanded.Length][];
        for (int i = 0; i < expanded.Length; i++)
        {
            if (expanded[i] is null || expanded[i].Length == 0)
            {
                throw new InvalidOperationException($"Round key {i} is null or empty.");
            }

            snapshot[i] = (byte[])expanded[i].Clone();
        }

        Volatile.Write(ref _roundKeys, snapshot);
    }

    public byte[] EncryptBlock(byte[] block) => TransformBlock(block, decrypt: false);

    public byte[] DecryptBlock(byte[] block) => TransformBlock(block, decrypt: true);

    private byte[] TransformBlock(byte[] block, bool decrypt)
    {
        if (block is null)
        {
            throw new ArgumentNullException(nameof(block), "Block cannot be null.");
        }

        if (block.Length != BlockSizeBytes)
        {
            throw new ArgumentException($"Block must contain exactly {BlockSizeBytes} bytes.", nameof(block));
        }

        byte[][] keys = Volatile.Read(ref _roundKeys) ??
            throw new InvalidOperationException("Call SetKey before processing a block.");

        int halfSize = BlockSizeBytes / 2;
        byte[] left = block[..halfSize];
        byte[] right = block[halfSize..];

        for (int round = 0; round < keys.Length; round++)
        {
            int keyIndex = decrypt ? keys.Length - 1 - round : round;
            byte[] transformed = _roundTransformation.Transform(
                (byte[])right.Clone(), (byte[])keys[keyIndex].Clone());

            if (transformed is null || transformed.Length != halfSize)
            {
                throw new InvalidOperationException(
                    $"Round transformation must return exactly {halfSize} bytes.");
            }

            // L(i+1) = R(i); R(i+1) = L(i) XOR F(R(i), K(i)).
            for (int i = 0; i < halfSize; i++)
            {
                left[i] ^= transformed[i];
            }

            (left, right) = (right, left);
        }

        byte[] result = new byte[BlockSizeBytes];
        Buffer.BlockCopy(right, 0, result, 0, halfSize);
        Buffer.BlockCopy(left, 0, result, halfSize, halfSize);
        return result;
    }
}
