using Package01.Abstractions;
using Package01.BitOperations;
using Package01.Feistel;

namespace Package01.Des;

public sealed class DesCipher : ISymmetricBlockCipher
{
    private readonly FeistelNetwork _network =
        new(new DesKeyExpansion(), new DesRoundTransformation());

    public int BlockSizeBytes => 8;

    public void SetKey(byte[] key) => _network.SetKey(key);

    public byte[] EncryptBlock(byte[] block) => TransformBlock(block, decrypt: false);

    public byte[] DecryptBlock(byte[] block) => TransformBlock(block, decrypt: true);

    private byte[] TransformBlock(byte[] block, bool decrypt)
    {
        ArgumentNullException.ThrowIfNull(block);
        if (block.Length != BlockSizeBytes)
        {
            throw new ArgumentException("A DES block must contain eight bytes.", nameof(block));
        }

        byte[] initial = BitUtils.Permute(block, DesTables.InitialPermutation, true, 1);
        byte[] transformed = decrypt
            ? _network.DecryptBlock(initial)
            : _network.EncryptBlock(initial);
        return BitUtils.Permute(transformed, DesTables.FinalPermutation, true, 1);
    }
}
