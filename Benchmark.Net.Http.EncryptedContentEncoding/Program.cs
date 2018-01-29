using System;
using BenchmarkDotNet.Reports;
using BenchmarkDotNet.Running;

namespace Benchmark.Net.Http.EncryptedContentEncoding
{
    class Program
    {
        static void Main(string[] args)
        {
            Summary serverSentEventsServiceSummary = BenchmarkRunner.Run<Aes128GcmEncodingBenchmarks>();

            Console.ReadKey();
        }
    }
}
