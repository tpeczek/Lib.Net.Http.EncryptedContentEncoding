using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Collections.Generic;
using Xunit;
using Lib.Net.Http.EncryptedContentEncoding;

namespace Test.Net.Http.EncryptedContentEncoding
{
    public class Aes128GcmEncodingTests
    {
        #region Fields
        private const string NON_RANDOM_SALT = "I1BsxtFttlv3u/Oo94xnmw==";

        private const string DEFAULT_KEY_ID = "";
        private const string NON_DEFAULT_KEY_ID = "a1";

        private static readonly IDictionary<string, byte[]> KEYS = new Dictionary<string, byte[]>
        {
            { DEFAULT_KEY_ID, Convert.FromBase64String("yqdlZ+tYemfogSmv7Ws5PQ==") },
            { NON_DEFAULT_KEY_ID, Convert.FromBase64String("BO3ZVPxUlnLORbVGMpbT1Q==") }
        };

        private const int RECORD_SIZE_4096 = 4096;

        private const string WALRUS_CONTENT = "I am the walrus";
        private const string WALRUS_CONTENT_ENCODED_AS_SINGLE_RECORD_BASE64 = "I1BsxtFttlv3u/Oo94xnmwAAEAAA+NAVub2qFgBEuQKRapoZu+IxkIva3MEB1PD+ly8Thjg=";
        private const string WALRUS_CONTENT_ENCODED_AS_MULTIPLE_RECORDS_WITHOUT_PADDING_BASE64 = "cQYlMQCQnOLX7EcBNqgB6gAAABkCYTG4EEuWeVUeiowUtpt4URB/f1ZZgaw4becqiWCPovDcJcJNtCEyTclEzJiBS4aHcVL2";
        private const string WALRUS_CONTENT_ENCODED_AS_MULTIPLE_RECORDS_WITH_PADDING_BASE64 = "uNCkWiNYzKTnBN9ji3+qWAAAABkCYTHOG8chz/gnvgOqdGYovxyjuqRyJFjEDyoF1Fvkj6hQPdPHI51OEUKEpgz3SsLWIqS/uA==";
        #endregion

        #region Tests
        [Fact]
        public async Task EncodeAsync_WalrusContentNonRandomSaltDefaultKeyRecordSize4096_EncodesAsSingleRecord()
        {
            byte[] contentToEncode = Encoding.UTF8.GetBytes(WALRUS_CONTENT);
            byte[] salt = Convert.FromBase64String(NON_RANDOM_SALT);

            string encodedContent = null;
            using (MemoryStream source = new MemoryStream(contentToEncode))
            {
                using (MemoryStream destination = new MemoryStream())
                {
                    await Aes128GcmEncoding.EncodeAsync(source, destination, salt, KEYS[DEFAULT_KEY_ID], (byte[])null, RECORD_SIZE_4096);

                    encodedContent = Convert.ToBase64String(destination.ToArray());
                }
            }
            
            Assert.Equal(WALRUS_CONTENT_ENCODED_AS_SINGLE_RECORD_BASE64, encodedContent);
        }

        [Fact]
        public async Task DecodeAsync_WalrusEncodedAsSingleRecord_DecodesWalrusContent()
        {
            byte[] contentToDecode = Convert.FromBase64String(WALRUS_CONTENT_ENCODED_AS_SINGLE_RECORD_BASE64);

            string decodedContent = null;
            using (MemoryStream source = new MemoryStream(contentToDecode))
            {
                using (MemoryStream destination = new MemoryStream())
                {
                    await Aes128GcmEncoding.DecodeAsync(source, destination, (keyId) => KEYS[keyId ?? DEFAULT_KEY_ID]);
                    decodedContent = Encoding.UTF8.GetString(destination.ToArray());
                }
            }

            Assert.Equal(WALRUS_CONTENT, decodedContent);
        }

        [Fact]
        public async Task DecodeAsync_WalrusEncodedAsMultipleRecordsWithoutPadding_DecodesWalrusContent()
        {
            byte[] contentToDecode = Convert.FromBase64String(WALRUS_CONTENT_ENCODED_AS_MULTIPLE_RECORDS_WITHOUT_PADDING_BASE64);

            string decodedContent = null;
            using (MemoryStream source = new MemoryStream(contentToDecode))
            {
                using (MemoryStream destination = new MemoryStream())
                {
                    await Aes128GcmEncoding.DecodeAsync(source, destination, (keyId) => KEYS[keyId ?? DEFAULT_KEY_ID]);
                    decodedContent = Encoding.UTF8.GetString(destination.ToArray());
                }
            }

            Assert.Equal(WALRUS_CONTENT, decodedContent);
        }

        [Fact]
        public async Task DecodeAsync_WalrusEncodedAsMultipleRecordsWithPadding_DecodesWalrusContent()
        {
            byte[] contentToDecode = Convert.FromBase64String(WALRUS_CONTENT_ENCODED_AS_MULTIPLE_RECORDS_WITH_PADDING_BASE64);

            string decodedContent = null;
            using (MemoryStream source = new MemoryStream(contentToDecode))
            {
                using (MemoryStream destination = new MemoryStream())
                {
                    await Aes128GcmEncoding.DecodeAsync(source, destination, (keyId) => KEYS[keyId ?? DEFAULT_KEY_ID]);
                    decodedContent = Encoding.UTF8.GetString(destination.ToArray());
                }
            }

            Assert.Equal(WALRUS_CONTENT, decodedContent);
        }
        #endregion
    }
}
