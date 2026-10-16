namespace Package01.Demo.Tests;

internal sealed record TestCase(string Name, Func<Task> Run);

internal static class TestSupport
{
    internal static async Task<(int Total, int Failed)> RunAsync(
        IReadOnlyList<TestCase> tests)
    {
        int failed = 0;
        foreach (TestCase test in tests)
        {
            try
            {
                await test.Run();
                Console.WriteLine($"[PASS] {test.Name}");
            }
            catch (Exception exception) when (exception is not OutOfMemoryException)
            {
                failed++;
                Console.Error.WriteLine($"[FAIL] {test.Name}: {exception}");
            }
        }

        return (tests.Count, failed);
    }

    internal static void AddTest(List<TestCase> tests, string name, Action test) =>
        tests.Add(new TestCase(name, () =>
        {
            test();
            return Task.CompletedTask;
        }));

    internal static void AddAsyncTest(
        List<TestCase> tests, string name, Func<Task> test) =>
        tests.Add(new TestCase(name, test));

    internal static void Assert(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }

    internal static void AssertEqual(
        byte[] expected,
        byte[]? actual,
        string message = "Byte arrays differ.")
    {
        if (actual is null || !expected.AsSpan().SequenceEqual(actual))
        {
            throw new InvalidOperationException(message);
        }
    }

    internal static void AssertThrows<TException>(Action action)
        where TException : Exception
    {
        try
        {
            action();
        }
        catch (TException)
        {
            return;
        }

        throw new InvalidOperationException(
            $"Expected {typeof(TException).Name}, but no exception was thrown.");
    }

    internal static async Task AssertThrowsAsync<TException>(Func<Task> action)
        where TException : Exception
    {
        try
        {
            await action();
        }
        catch (TException)
        {
            return;
        }

        throw new InvalidOperationException(
            $"Expected {typeof(TException).Name}, but no exception was thrown.");
    }
}
