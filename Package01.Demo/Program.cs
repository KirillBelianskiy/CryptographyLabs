using Package01.Demo.Demonstrations;
using Package01.Demo.Tests;

namespace Package01.Demo;

internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        if (args.Length == 1 && args[0] is "--help" or "-h")
        {
            PrintUsage();
            return 0;
        }

        string selection = args.Length == 0 ? "all" : args[0].ToLowerInvariant();
        if (args.Length > 2 || selection is not ("all" or "1" or "2" or "3" or "4" or "5" or "6" or "7"))
        {
            Console.Error.WriteLine("Choose a task from 1 to 7, or all.");
            PrintUsage();
            return 2;
        }

        string outputDirectory = args.Length == 2 ? args[1] : "demo-output";
        (int Number, string Name, Func<Task<(int Total, int Failed)>> RunTests)[] laboratories =
        [
            (1, "Bit permutations", Lab01Tests.RunAsync),
            (2, "Symmetric cipher context, modes, padding and files", Lab02Tests.RunAsync),
            (3, "Feistel network", Lab03Tests.RunAsync),
            (4, "DES", Lab04Tests.RunAsync),
            (5, "DES arrays and files", () => CipherDemonstration.RunAsync(false, outputDirectory)),
            (6, "DEAL and DES round adapter", Lab06Tests.RunAsync),
            (7, "DEAL arrays and files", () => CipherDemonstration.RunAsync(true, outputDirectory))
        ];

        int total = 0;
        int failed = 0;
        foreach ((int number, string name, Func<Task<(int Total, int Failed)>> runTests) in laboratories)
        {
            if (selection != "all" && selection != number.ToString())
            {
                continue;
            }

            Console.WriteLine($"=== Lab {number}: {name} ===");
            (int count, int labFailed) = await runTests();
            if (number == 2)
            {
                (int regressionCount, int regressionFailed) = await RegressionTests.RunAsync();
                count += regressionCount;
                labFailed += regressionFailed;
            }

            total += count;
            failed += labFailed;
            Console.WriteLine($"Lab {number}: tests: {count}; passed: {count - labFailed}; failed: {labFailed}.");

            if (number == 2)
            {
                Console.WriteLine("Known limitation: Zeros padding removes original trailing zero bytes.");
                Console.WriteLine("Known limitation: a short-period RandomDelta can repeat masks.");
            }

            Console.WriteLine();
        }

        Console.WriteLine($"Total tests: {total}; passed: {total - failed}; failed: {failed}.");
        return failed == 0 ? 0 : 1;
    }

    private static void PrintUsage()
    {
        Console.WriteLine("Usage: dotnet run --project Package01.Demo -- [1|2|3|4|5|6|7|all] [output-directory]");
        Console.WriteLine("Without arguments, all seven tasks run. Demo files go to demo-output.");
    }
}
