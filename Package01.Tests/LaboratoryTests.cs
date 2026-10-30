using NUnit.Framework;

using Package01.Demo.Demonstrations;
using Package01.Demo.Tests;

namespace Package01.Tests;

[TestFixture]
[NonParallelizable]
public sealed class LaboratoryTests
{
    [TestCaseSource(nameof(CreateCases), new object[] { 1 })]
    public Task Lab01(Func<Task> run) => run();

    [TestCaseSource(nameof(CreateCases), new object[] { 2 })]
    public Task Lab02(Func<Task> run) => run();

    [TestCaseSource(nameof(CreateCases), new object[] { 3 })]
    public Task Lab03(Func<Task> run) => run();

    [TestCaseSource(nameof(CreateCases), new object[] { 4 })]
    public Task Lab04(Func<Task> run) => run();

    [TestCaseSource(nameof(CreateCases), new object[] { 5 })]
    public Task Lab05(Func<Task> run) => run();

    [TestCaseSource(nameof(CreateCases), new object[] { 6 })]
    public Task Lab06(Func<Task> run) => run();

    [TestCaseSource(nameof(CreateCases), new object[] { 7 })]
    public Task Lab07(Func<Task> run) => run();

    private static IEnumerable<TestCaseData> CreateCases(int laboratory)
    {
        IEnumerable<TestCase> tests = laboratory switch
        {
            1 => Lab01Tests.CreateTests(),
            2 => Lab02Tests.CreateTests().Concat(RegressionTests.CreateTests()),
            3 => Lab03Tests.CreateTests(),
            4 => Lab04Tests.CreateTests(),
            5 => CreateDemonstrationCases(useDeal: false),
            6 => Lab06Tests.CreateTests(),
            7 => CreateDemonstrationCases(useDeal: true),
            _ => throw new ArgumentOutOfRangeException(nameof(laboratory))
        };

        foreach (TestCase test in tests)
        {
            yield return new TestCaseData(test.Run)
                .SetName($"Lab{laboratory:00}: {test.Name}")
                .SetCategory($"Lab{laboratory:00}");
        }
    }

    private static IEnumerable<TestCase> CreateDemonstrationCases(bool useDeal)
    {
        string directory = Path.Combine(
            Path.GetTempPath(), $"CryptographyLabs.Tests.{Guid.NewGuid():N}");
        foreach (TestCase test in CipherDemonstration.CreateTests(useDeal, directory))
        {
            yield return new TestCase(test.Name, async () =>
            {
                try
                {
                    await test.Run();
                }
                finally
                {
                    if (Directory.Exists(directory))
                    {
                        Directory.Delete(directory, recursive: true);
                    }
                }
            });
        }
    }
}
