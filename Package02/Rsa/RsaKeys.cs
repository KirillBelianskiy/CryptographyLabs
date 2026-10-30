using System.Numerics;

namespace Package02.Rsa;

public sealed record RsaPublicKey(BigInteger Modulus, BigInteger Exponent);

public sealed record RsaPrivateKey(BigInteger Modulus, BigInteger Exponent);

public sealed record RsaKeyPair(RsaPublicKey PublicKey, RsaPrivateKey PrivateKey, BigInteger P, BigInteger Q)
{
    public BigInteger EulerPhi => (P - 1) * (Q - 1);
}
