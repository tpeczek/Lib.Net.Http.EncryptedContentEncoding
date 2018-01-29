using Benchmark.Net.Http.EncryptedContentEncoding.Infrastructure;
using BenchmarkDotNet.Attributes;
using Lib.Net.Http.EncryptedContentEncoding;
using System;
using System.IO;
using System.Threading.Tasks;

namespace Benchmark.Net.Http.EncryptedContentEncoding
{
    [MemoryDiagnoser]
    public class Aes128GcmEncodingBenchmarks
    {
        #region Fields
        private const string KEY_ID = "a1";
        private static readonly byte[] KEY = Convert.FromBase64String("BO3ZVPxUlnLORbVGMpbT1Q ==");

        private const int RECORD_SIZE_4096 = 4096;

        private MemoryStream _encodeSingleRecordSource;
        private MemoryStream _encodeMultipleRecordsSource;
        private MemoryStream _decodeSingleRecordSource;
        private MemoryStream _decodeMultipleRecordsSource;
        #endregion

        #region Benchmarks
        [GlobalSetup(Target = nameof(EncodeSingleRecordAsync))]
        public void SetupEncodeSingleRecordSource()
        {
            _encodeSingleRecordSource = new MemoryStream(LoremIpsum.LOREM_IPSUM_4079);
        }

        [Benchmark]
        public Task EncodeSingleRecordAsync()
        {
            _encodeSingleRecordSource.Seek(0, SeekOrigin.Begin);
            return Aes128GcmEncoding.EncodeAsync(_encodeSingleRecordSource, Stream.Null, KEY, KEY_ID, RECORD_SIZE_4096);
        }

        [GlobalCleanup(Target = nameof(EncodeSingleRecordAsync))]
        public void CleanupEncodeSingleRecordSource()
        {
            _encodeSingleRecordSource.Dispose();
            _encodeSingleRecordSource = null;
        }

        [GlobalSetup(Target = nameof(EncodeMultipleRecordsAsync))]
        public void SetupEncodeMultipleRecordsSource()
        {
            _encodeMultipleRecordsSource = new MemoryStream(LoremIpsum.LOREM_IPSUM_40790);
        }

        [Benchmark]
        public Task EncodeMultipleRecordsAsync()
        {
            _encodeMultipleRecordsSource.Seek(0, SeekOrigin.Begin);
            return Aes128GcmEncoding.EncodeAsync(_encodeMultipleRecordsSource, Stream.Null, KEY, KEY_ID, RECORD_SIZE_4096);
        }

        [GlobalCleanup(Target = nameof(EncodeMultipleRecordsAsync))]
        public void CleanupEncodeMultipleRecordsSource()
        {
            _encodeMultipleRecordsSource.Dispose();
            _encodeMultipleRecordsSource = null;
        }

        [GlobalSetup(Target = nameof(DecodeSingleRecordAsync))]
        public void SetupDecodeSingleRecordSource()
        {
            _decodeSingleRecordSource = new MemoryStream(LoremIpsum.LOREM_IPSUM_4079_ENCODED);
        }

        [Benchmark]
        public Task DecodeSingleRecordAsync()
        {
            _decodeSingleRecordSource.Seek(0, SeekOrigin.Begin);
            return Aes128GcmEncoding.DecodeAsync(_decodeSingleRecordSource, Stream.Null, (string keyId) => KEY);
        }

        [GlobalCleanup(Target = nameof(DecodeSingleRecordAsync))]
        public void CleanupDecodeSingleRecordSource()
        {
            _decodeSingleRecordSource.Dispose();
            _decodeSingleRecordSource = null;
        }

        [GlobalSetup(Target = nameof(DecodeMultipleRecordsAsync))]
        public void SetupDecodeMultipleRecordsSource()
        {
            _decodeMultipleRecordsSource = new MemoryStream(LoremIpsum.LOREM_IPSUM_40790_ENCODED);
        }

        [Benchmark]
        public Task DecodeMultipleRecordsAsync()
        {
            _decodeMultipleRecordsSource.Seek(0, SeekOrigin.Begin);
            return Aes128GcmEncoding.DecodeAsync(_decodeMultipleRecordsSource, Stream.Null, (string keyId) => KEY);
        }

        [GlobalCleanup(Target = nameof(DecodeMultipleRecordsAsync))]
        public void CleanupDecodeMultipleRecordsSource()
        {
            _decodeMultipleRecordsSource.Dispose();
            _decodeMultipleRecordsSource = null;
        }
        #endregion
    }
}
