namespace Package01.Abstractions;

public interface ISymmetricBlockCipher
{
    int BlockSizeBytes { get; }

    void SetKey(byte[] key);

    byte[] EncryptBlock(byte[] block);

    byte[] DecryptBlock(byte[] block);
}
