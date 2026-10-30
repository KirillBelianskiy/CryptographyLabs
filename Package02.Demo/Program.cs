using System.Numerics;
using System.Text;

using Package02.Arithmetic;
using Package02.Primality;
using Package02.Rsa;

Console.OutputEncoding = Encoding.UTF8;
Console.WriteLine("Пакет 2. Учебные реализации; textbook RSA без OAEP.");
Console.WriteLine("\nЗадание 1. Теоретико-числовой сервис");
Console.WriteLine($"Лежандр (5/11) = {NumberTheory.Legendre(5, 11)}");
Console.WriteLine($"Якоби (5/21) = {NumberTheory.Jacobi(5, 21)}");
Console.WriteLine($"НОД(240, 46) = {NumberTheory.Gcd(240, 46)}");
BezoutResult bezout = NumberTheory.ExtendedGcd(240, 46);
Console.WriteLine($"Безу: 240 * {bezout.X} + 46 * {bezout.Y} = {bezout.Gcd}");
Console.WriteLine($"Бинарный НОД(240, 46) = {NumberTheory.BinaryGcd(240, 46)}");
Console.WriteLine($"7^128 mod 13 = {NumberTheory.ModPow(7, 128, 13)}");
Console.WriteLine($"φ(36): определение = {NumberTheory.EulerByDefinition(36)}, " +
    $"факторизация = {NumberTheory.EulerByFactorization(36)}, ДПФ = {NumberTheory.EulerByFourier(36)}");
Console.WriteLine($"λ(360) = {NumberTheory.Carmichael(360)}");

Console.WriteLine("\nЗадание 2. Вероятностные тесты");
ProbabilisticPrimalityTest[] tests =
[
    new FermatPrimalityTest(),
    new SolovayStrassenPrimalityTest(),
    new MillerRabinPrimalityTest()
];
foreach (ProbabilisticPrimalityTest test in tests)
{
    Console.WriteLine($"{test.GetType().Name}: 101 = {test.IsProbablePrime(101, 0.999999)}, " +
        $"561 = {test.IsProbablePrime(561, 0.999999)}");
}

Console.WriteLine($"Число Кармайкла 561 проходит итерацию Ферма с основанием 2: " +
    $"{new FermatPrimalityTest().PassesRound(561, 2)}");
Console.WriteLine("Положительный итог Ферма дополнительно подтверждается Миллером—Рабином.");

Console.WriteLine("\nЗадание 3. RSA: все три варианта теста и повторная генерация");
byte[] plaintext = Encoding.UTF8.GetBytes("Привет, RSA!\0\0");
foreach (RsaService.PrimalityTestKind kind in Enum.GetValues<RsaService.PrimalityTestKind>())
{
    var service = new RsaService(kind, 0.999999, 64);
    for (int generation = 1; generation <= 2; generation++)
    {
        RsaKeyPair pair = service.GenerateKeyPair();
        byte[] ciphertext = service.Encrypt(plaintext);
        byte[] restored = service.Decrypt(ciphertext);
        if (!plaintext.SequenceEqual(restored))
        {
            throw new InvalidOperationException("RSA round trip failed.");
        }

        Console.WriteLine($"{kind}, пара {generation}: n = {pair.PublicKey.Modulus}, e = {pair.PublicKey.Exponent}");
        Console.WriteLine($"  Шифртекст: {Convert.ToHexString(ciphertext)}");
        Console.WriteLine($"  Восстановлено {restored.Length} байт: {Encoding.UTF8.GetString(restored).TrimEnd('\0')}");
        BigInteger root = NumberTheory.IntegerSquareRoot(pair.PublicKey.Modulus);
        BigInteger ceilRoot = root * root == pair.PublicKey.Modulus ? root : root + 1;
        Console.WriteLine($"  Итераций Ферма до факторов: {(pair.P + pair.Q) / 2 - ceilRoot}");
        Console.WriteLine($"  Атака Винера успешна: {new WienerAttackService().Attack(pair.PublicKey).Success}");
    }
}

Console.WriteLine("\nЗадание 4. Атака Винера на намеренно уязвимый ключ");
var vulnerableGenerator = new WienerVulnerableKeyGenerator();
for (int i = 0; i < 3; i++)
{
    RsaKeyPair pair = vulnerableGenerator.Generate();
    WienerAttackResult result = new WienerAttackService().Attack(pair.PublicKey);
    if (result.PrivateExponent != pair.PrivateKey.Exponent || result.EulerPhi != pair.EulerPhi)
    {
        throw new InvalidOperationException("Wiener's attack failed to recover the vulnerable key.");
    }

    Console.WriteLine($"n = {pair.PublicKey.Modulus}, e = {pair.PublicKey.Exponent}");
    Console.WriteLine($"Найдены d = {result.PrivateExponent}, φ(n) = {result.EulerPhi}");
    Console.WriteLine("Подходящие дроби e/n: " + string.Join(", ",
        result.Convergents.Select(fraction => $"{fraction.Numerator}/{fraction.Denominator}")));
}
