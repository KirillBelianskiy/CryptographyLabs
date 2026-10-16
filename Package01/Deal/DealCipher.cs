using Package01.Abstractions;
using Package01.Feistel;

namespace Package01.Deal;

public sealed class DealCipher : ISymmetricBlockCipher
{
    private readonly FeistelNetwork _network =
        new(new DealKeyExpansion(), new DesRoundAdapter(), 16);

    public int BlockSizeBytes => 16;

    public void SetKey(byte[] key) => _network.SetKey(key);

    public byte[] EncryptBlock(byte[] block) => SwapHalves(_network.EncryptBlock(block));

    public byte[] DecryptBlock(byte[] block) => _network.DecryptBlock(SwapHalves(block));

    private static byte[] SwapHalves(byte[] block)
    {
        ArgumentNullException.ThrowIfNull(block);
        if (block.Length != 16)
        {
            throw new ArgumentException("A DEAL block must contain sixteen bytes.", nameof(block));
        }

        // DEAL writes A | B; the reusable network writes R | L.
        byte[] result = new byte[16];
        block.AsSpan(8).CopyTo(result);
        block.AsSpan(0, 8).CopyTo(result.AsSpan(8));
        return result;
    }
}
