using Package01.Abstractions;
using Package01.Des;

namespace Package01.Deal;

public sealed class DesRoundAdapter : IRoundTransformation
{
    public byte[] Transform(byte[] inputBlock, byte[] roundKey)
    {
        // Local state keeps simultaneous round calls independent.
        var cipher = new DesCipher();
        cipher.SetKey(roundKey);
        return cipher.EncryptBlock(inputBlock);
    }
}
