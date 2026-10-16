namespace Package01.Abstractions;

public interface IRoundTransformation
{
    byte[] Transform(byte[] inputBlock, byte[] roundKey);
}
