using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace Lib.Net.Http.EncryptedContentEncoding
{
    /// <summary>
    /// Provides aes128gcm encoding and decoding routines.
    /// </summary>
    public static class Aes128GcmEncoding
    {
        #region Structs
        private readonly struct CodingHeader
        {
            public byte[] Salt { get; }

            public int RecordSize { get; }

            public byte[] KeyId { get; }

            public CodingHeader(byte[] salt, int recordSize, byte[] keyId)
            {
                Salt = salt;
                RecordSize = recordSize;
                KeyId = keyId;
            }
        }
        #endregion

        #region Fields
        private const int SALT_INDEX = 0;
        private const int SALT_LENGTH = 16;

        private const int RECORD_ENCRYPTION_OVERHEAD_SIZE = 16;
        private const int RECORD_DELIMITER_SIZE = 1;
        private const int MIN_RECORD_SIZE = RECORD_ENCRYPTION_OVERHEAD_SIZE + RECORD_DELIMITER_SIZE + 1;

        internal const int DEFAULT_RECORD_SIZE = 4096;        
        private const int RECORD_SIZE_INDEX = SALT_INDEX + SALT_LENGTH;
        private const int RECORD_SIZE_LENGTH = 4;

        private const int KEY_ID_LEN_INDEX = RECORD_SIZE_INDEX + RECORD_SIZE_LENGTH;
        private const int KEY_ID_LEN_LENGTH = 1;
        private const int KEY_ID_INDEX = KEY_ID_LEN_INDEX + KEY_ID_LEN_LENGTH;

        private const byte INFO_PARAMETER_DELIMITER = 1;

        private const byte RECORD_DELIMITER = 1;
        private const byte LAST_RECORD_DELIMITER = 2;

        private const int CONTENT_ENCRYPTION_KEY_LENGTH = 16;

        private const int NONCE_LENGTH = 12;

        private static readonly byte[] _emptyKeyId = new byte[0];
        // CEK_INFO = "Content-Encoding: aes128gcm" || 0x00 || 0x01
        private static readonly byte[] _contentEncryptionKeyInfoParameter = GetInfoParameter("Content-Encoding: aes128gcm");
        // NONCE_INFO = "Content-Encoding: nonce" || 0x00 || 0x01
        private static readonly byte[] _nonceInfoParameter = GetInfoParameter("Content-Encoding: nonce");
        private static readonly SecureRandom _secureRandom = new SecureRandom();
        #endregion

        #region Public Methods
        /// <summary>
        /// Encodes source stream into destionation stream as an asynchronous operation.
        /// </summary>
        /// <param name="source">The source stream.</param>
        /// <param name="destination">The destionation stream.</param>
        /// <param name="key">The keying material.</param>
        /// <returns>The task object representing the asynchronous operation.</returns>
        public static Task EncodeAsync(Stream source, Stream destination, byte[] key)
        {
            return EncodeAsync(source, destination, null, key, (byte[])null, DEFAULT_RECORD_SIZE);
        }

        /// <summary>
        /// Encodes source stream into destionation stream as an asynchronous operation.
        /// </summary>
        /// <param name="source">The source stream.</param>
        /// <param name="destination">The destionation stream.</param>
        /// <param name="key">The keying material.</param>
        /// <param name="keyId">The keying material identificator.</param>
        /// <returns>The task object representing the asynchronous operation.</returns>
        public static Task EncodeAsync(Stream source, Stream destination, byte[] key, string keyId)
        {
            return EncodeAsync(source, destination, null, key, keyId, DEFAULT_RECORD_SIZE);
        }

        /// <summary>
        /// Encodes source stream into destionation stream as an asynchronous operation.
        /// </summary>
        /// <param name="source">The source stream.</param>
        /// <param name="destination">The destionation stream.</param>
        /// <param name="key">The keying material.</param>
        /// <param name="keyId">The keying material identificator.</param>
        /// <returns>The task object representing the asynchronous operation.</returns>
        public static Task EncodeAsync(Stream source, Stream destination, byte[] key, byte[] keyId)
        {
            return EncodeAsync(source, destination, null, key, keyId, DEFAULT_RECORD_SIZE);
        }

        /// <summary>
        /// Encodes source stream into destionation stream as an asynchronous operation.
        /// </summary>
        /// <param name="source">The source stream.</param>
        /// <param name="destination">The destionation stream.</param>
        /// <param name="key">The keying material.</param>
        /// <param name="recordSize">The record size in octets.</param>
        /// <returns>The task object representing the asynchronous operation.</returns>
        public static Task EncodeAsync(Stream source, Stream destination, byte[] key, int recordSize)
        {
            return EncodeAsync(source, destination, null, key, (byte[])null, recordSize);
        }

        /// <summary>
        /// Encodes source stream into destionation stream as an asynchronous operation.
        /// </summary>
        /// <param name="source">The source stream.</param>
        /// <param name="destination">The destionation stream.</param>
        /// <param name="key">The keying material.</param>
        /// <param name="keyId">The keying material identificator.</param>
        /// <param name="recordSize">The record size in octets.</param>
        /// <returns>The task object representing the asynchronous operation.</returns>
        public static Task EncodeAsync(Stream source, Stream destination, byte[] key, string keyId, int recordSize)
        {
            return EncodeAsync(source, destination, null, key, keyId, recordSize);
        }

        /// <summary>
        /// Encodes source stream into destionation stream as an asynchronous operation.
        /// </summary>
        /// <param name="source">The source stream.</param>
        /// <param name="destination">The destionation stream.</param>
        /// <param name="key">The keying material.</param>
        /// <param name="keyId">The keying material identificator.</param>
        /// <param name="recordSize">The record size in octets.</param>
        /// <returns>The task object representing the asynchronous operation.</returns>
        public static Task EncodeAsync(Stream source, Stream destination, byte[] key, byte[] keyId, int recordSize)
        {
            return EncodeAsync(source, destination, null, key, keyId, recordSize);
        }

        /// <summary>
        /// Encodes source stream into destionation stream as an asynchronous operation.
        /// </summary>
        /// <param name="source">The source stream.</param>
        /// <param name="destination">The destionation stream.</param>
        /// <param name="salt">The salt.</param>
        /// <param name="key">The keying material.</param>
        /// <param name="keyId">The keying material identificator.</param>
        /// <param name="recordSize">The record size in octets.</param>
        /// <returns>The task object representing the asynchronous operation.</returns>
        public static Task EncodeAsync(Stream source, Stream destination, byte[] salt, byte[] key, string keyId, int recordSize)
        {
            byte[] keyIdBytes = String.IsNullOrEmpty(keyId) ? new byte[0] : Encoding.UTF8.GetBytes(keyId);

            return EncodeAsync(source, destination, salt, key, keyIdBytes, recordSize);
        }

        /// <summary>
        /// Encodes source stream into destionation stream as an asynchronous operation.
        /// </summary>
        /// <param name="source">The source stream.</param>
        /// <param name="destination">The destionation stream.</param>
        /// <param name="salt">The salt.</param>
        /// <param name="key">The keying material.</param>
        /// <param name="keyId">The keying material identificator.</param>
        /// <param name="recordSize">The record size in octets.</param>
        /// <returns>The task object representing the asynchronous operation.</returns>
        public static async Task EncodeAsync(Stream source, Stream destination, byte[] salt, byte[] key, byte[] keyId, int recordSize)
        {
            ValidateEncodeParameters(source, destination, key, keyId, recordSize);

            CodingHeader codingHeader = new CodingHeader(CoalesceSalt(salt), recordSize, keyId ?? _emptyKeyId);

            // PRK = HMAC-SHA-256(salt, IKM)
            byte[] pseudorandomKey = HmacSha256(codingHeader.Salt, key);

            byte[] contentEncryptionKeyInfoParameterHash, nonceInfoParameterHash;
            using (HMACSHA256 pseudorandomKeyHasher = new HMACSHA256(pseudorandomKey))
            {
                // HMAC-SHA-256(PRK, CEK_INFO)
                contentEncryptionKeyInfoParameterHash = HmacSha256(pseudorandomKeyHasher, _contentEncryptionKeyInfoParameter);

                // HMAC-SHA-256(PRK, NONCE_INFO)
                nonceInfoParameterHash = HmacSha256(pseudorandomKeyHasher, _nonceInfoParameter);
            }

            await WriteCodingHeaderAsync(destination, codingHeader).ConfigureAwait(false);

            await EncryptContentAsync(source, destination, codingHeader.RecordSize, contentEncryptionKeyInfoParameterHash, nonceInfoParameterHash).ConfigureAwait(false);
        }

        /// <summary>
        /// Decodes source stream into destionation stream as an asynchronous operation.
        /// </summary>
        /// <param name="source">The source stream.</param>
        /// <param name="destination">The destionation stream.</param>
        /// <param name="keyProvider">The function which is able to provide the keying material based on the keying material identificator.</param>
        /// <returns>The task object representing the asynchronous operation.</returns>
        public static Task DecodeAsync(Stream source, Stream destination, Func<string, byte[]> keyProvider)
        {
            return DecodeAsync(source, destination, ConvertToByteArrayBasedKeyProvider(keyProvider));
        }

        /// <summary>
        /// Decodes source stream into destionation stream as an asynchronous operation.
        /// </summary>
        /// <param name="source">The source stream.</param>
        /// <param name="destination">The destionation stream.</param>
        /// <param name="keyProvider">The function which is able to provide the keying material based on the keying material identificator.</param>
        /// <returns>The task object representing the asynchronous operation.</returns>
        public static async Task DecodeAsync(Stream source, Stream destination, Func<byte[], byte[]> keyProvider)
        {
            ValidateDecodeParameters(source, destination, keyProvider);

            CodingHeader codingHeader = await ReadCodingHeaderAsync(source).ConfigureAwait(false);

            // PRK = HMAC-SHA-256(salt, IKM)
            byte[] pseudorandomKey = HmacSha256(codingHeader.Salt, keyProvider(codingHeader.KeyId));

            byte[] contentEncryptionKeyInfoParameterHash, nonceInfoParameterHash;
            using (HMACSHA256 pseudorandomKeyHasher = new HMACSHA256(pseudorandomKey))
            {
                // HMAC-SHA-256(PRK, CEK_INFO)
                contentEncryptionKeyInfoParameterHash = HmacSha256(pseudorandomKeyHasher, _contentEncryptionKeyInfoParameter);

                // HMAC-SHA-256(PRK, NONCE_INFO)
                nonceInfoParameterHash = HmacSha256(pseudorandomKeyHasher, _nonceInfoParameter);
            }

            await DecryptContentAsync(source, destination, codingHeader.RecordSize, contentEncryptionKeyInfoParameterHash, nonceInfoParameterHash).ConfigureAwait(false);
        }

        internal static Func<byte[], byte[]> ConvertToByteArrayBasedKeyProvider(Func<string, byte[]> stringBasedKeyProvider)
        {
            return (byte[] keyId) => stringBasedKeyProvider((keyId == null) ? null : Encoding.UTF8.GetString(keyId));
        }
        #endregion

        #region General Private Methods
        private static byte[] GetInfoParameter(string infoParameterString)
        {
            byte[] infoParameter = new byte[infoParameterString.Length + 2];

            Encoding.ASCII.GetBytes(infoParameterString, 0, infoParameterString.Length, infoParameter, 0);

            infoParameter[infoParameter.Length - 1] = INFO_PARAMETER_DELIMITER;

            return infoParameter;
        }

        private static byte[] HmacSha256(byte[] key, byte[] value)
        {
            byte[] hash = null;

            using (HMACSHA256 hasher = new HMACSHA256(key))
            {
                hash = HmacSha256(hasher, value);
            }

            return hash;
        }

        private static byte[] HmacSha256(HMACSHA256 hasher, byte[] value)
        {
            return hasher.ComputeHash(value);
        }

        private static byte[] XorNonce(byte[] nonceInfoParameterHash, ulong recordSequenceNumber)
        {
            // NONCE = FIRST 12 OCTETS OF HMAC-SHA-256(PRK, NONCE_INFO) XOR SEQ
            byte[] nonce = new byte[NONCE_LENGTH];

            nonce[0] =  (byte)(nonceInfoParameterHash[0] ^ 0);
            nonce[1] =  (byte)(nonceInfoParameterHash[1] ^ 0);
            nonce[2] =  (byte)(nonceInfoParameterHash[2] ^ 0);
            nonce[3] =  (byte)(nonceInfoParameterHash[3] ^ 0);
            nonce[4] =  (byte)(nonceInfoParameterHash[4]  ^ (byte)(recordSequenceNumber >> 56));
            nonce[5] =  (byte)(nonceInfoParameterHash[5]  ^ (byte)(recordSequenceNumber >> 48));
            nonce[6] =  (byte)(nonceInfoParameterHash[6]  ^ (byte)(recordSequenceNumber >> 40));
            nonce[7] =  (byte)(nonceInfoParameterHash[7]  ^ (byte)(recordSequenceNumber >> 32));
            nonce[8] =  (byte)(nonceInfoParameterHash[8]  ^ (byte)(recordSequenceNumber >> 24));
            nonce[9] =  (byte)(nonceInfoParameterHash[9]  ^ (byte)(recordSequenceNumber >> 16));
            nonce[10] = (byte)(nonceInfoParameterHash[10] ^ (byte)(recordSequenceNumber >> 8));
            nonce[11] = (byte)(nonceInfoParameterHash[11] ^ (byte)(recordSequenceNumber));

            return nonce;
        }

        private static void ConfigureAes128GcmCipher(GcmBlockCipher aes128GcmCipher, bool forEncryption, KeyParameter key, byte[] nonceInfoParameterHash, ulong recordSequenceNumber)
        {
            aes128GcmCipher.Reset();
            AeadParameters aes128GcmParameters = new AeadParameters(key, 128, XorNonce(nonceInfoParameterHash, recordSequenceNumber));
            aes128GcmCipher.Init(forEncryption, aes128GcmParameters);
        }

        private static int Aes128GcmCipherProcessBytes(GcmBlockCipher aes128GcmCipher, byte[] bytesToProcess, int bytesToProcessLength, byte[] processedBytesBuffer)
        {
            int processBytesCount = aes128GcmCipher.ProcessBytes(bytesToProcess, 0, bytesToProcessLength, processedBytesBuffer, 0);
            int doFinalBytesCount = aes128GcmCipher.DoFinal(processedBytesBuffer, processBytesCount);

            return processBytesCount + doFinalBytesCount;
        }
        #endregion

        #region Encode Private Methods
        private static void ValidateEncodeParameters(Stream source, Stream destination, byte[] key, byte[] keyId, int recordSize)
        {
            if (source == null)
            {
                throw new ArgumentNullException(nameof(source));
            }

            if (destination == null)
            {
                throw new ArgumentNullException(nameof(destination));
            }

            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if ((keyId != null) && (keyId.Length > Byte.MaxValue))
            {
                throw new ArgumentException($"The '{nameof(keyId)}' parameter is too long.", nameof(keyId));
            }

            if (recordSize < MIN_RECORD_SIZE)
            {
                throw new ArgumentException($" The '{nameof(recordSize)}' parameter must be at least {MIN_RECORD_SIZE}.", nameof(recordSize));
            }
        }

        private static byte[] CoalesceSalt(byte[] salt)
        {
            if (salt == null)
            {
                salt = new byte[SALT_LENGTH];
                _secureRandom.NextBytes(salt, 0, SALT_LENGTH);
            }
            else if (salt.Length != SALT_LENGTH)
            {
                throw new ArgumentException($" The '{nameof(salt)}' parameter must be {SALT_LENGTH} octets long.", nameof(salt));
            }

            return salt;
        }

        private static void WriteRecordSize(Stream destination, int recordSize)
        {
            destination.WriteByte((byte)(recordSize >> 24));
            destination.WriteByte((byte)(recordSize >> 16));
            destination.WriteByte((byte)(recordSize >> 8));
            destination.WriteByte((byte)(recordSize));
        }

        private static async Task WriteCodingHeaderAsync(Stream destination, CodingHeader codingHeader)
        {
            //+----------+---------------+-------------+-----------------+
            //| SALT(16) | RECORDSIZE(4) | KEYIDLEN(1) | KEYID(KEYIDLEN) |
            //+----------+---------------+-------------+-----------------+

            await destination.WriteAsync(codingHeader.Salt, 0, codingHeader.Salt.Length).ConfigureAwait(false);
            WriteRecordSize(destination, codingHeader.RecordSize);
            destination.WriteByte((byte)codingHeader.KeyId.Length);
            await destination.WriteAsync(codingHeader.KeyId, 0, codingHeader.KeyId.Length).ConfigureAwait(false);
        }

        private static async Task<int> GetPlainTextAsync(Stream source, byte[] plainTextBuffer, byte? peekedPlainTextByte)
        {
            int plainTextLength;

            int maxPlainTextLength = plainTextBuffer.Length - RECORD_DELIMITER_SIZE;

            if (peekedPlainTextByte.HasValue)
            {
                plainTextBuffer[0] = peekedPlainTextByte.Value;
                plainTextLength = (await source.ReadAsync(plainTextBuffer, 1, maxPlainTextLength - 1).ConfigureAwait(false)) + 1;
            }
            else
            {
                plainTextLength = await source.ReadAsync(plainTextBuffer, 0, maxPlainTextLength).ConfigureAwait(false);
            }

            if (plainTextLength == maxPlainTextLength)
            {
                plainTextBuffer[plainTextBuffer.Length - 1] = RECORD_DELIMITER;
            }
            else
            {
                plainTextBuffer[plainTextLength] = LAST_RECORD_DELIMITER;
            }

            return plainTextLength + 1;
        }

        private static async Task EncryptContentAsync(Stream source, Stream destination, int recordSize, byte[] contentEncryptionKeyInfoParameterHash, byte[] nonceInfoParameterHash)
        {
            // CEK = FIRST 16 OCTETS OF HMAC-SHA-256(PRK, CEK_INFO)
            KeyParameter key = new KeyParameter(contentEncryptionKeyInfoParameterHash, 0, CONTENT_ENCRYPTION_KEY_LENGTH);
            GcmBlockCipher aes128GcmCipher = new GcmBlockCipher(new AesFastEngine());

            ulong recordSequenceNumber = 0;

            int plainTextLength;
            byte[] plainTextBuffer = new byte[recordSize - RECORD_ENCRYPTION_OVERHEAD_SIZE];
            int? peekedPlainTextByte = null;

            byte[] cipherTextBuffer = new byte[recordSize];

            do
            {
                plainTextLength = await GetPlainTextAsync(source, plainTextBuffer, (byte?)peekedPlainTextByte).ConfigureAwait(false);

                if (plainTextBuffer[plainTextLength - 1] != LAST_RECORD_DELIMITER)
                {
                    peekedPlainTextByte = source.ReadByte();
                    if (peekedPlainTextByte == -1)
                    {
                        plainTextBuffer[plainTextLength - 1] = LAST_RECORD_DELIMITER;
                    }
                }

                ConfigureAes128GcmCipher(aes128GcmCipher, true, key, nonceInfoParameterHash, recordSequenceNumber++);
                int cipherTextLength = Aes128GcmCipherProcessBytes(aes128GcmCipher, plainTextBuffer, plainTextLength, cipherTextBuffer);

                await destination.WriteAsync(cipherTextBuffer, 0, cipherTextLength).ConfigureAwait(false);
            }
            while (plainTextBuffer[plainTextLength - 1] != LAST_RECORD_DELIMITER);
        }
        #endregion

        #region Decode Private Methods
        private static void ValidateDecodeParameters(Stream source, Stream destination, Func<byte[], byte[]> keyProvider)
        {
            if (source == null)
            {
                throw new ArgumentNullException(nameof(source));
            }

            if (destination == null)
            {
                throw new ArgumentNullException(nameof(destination));
            }

            if (keyProvider == null)
            {
                throw new ArgumentNullException(nameof(keyProvider));
            }
        }

        private static void ThrowInvalidCodingHeaderException()
        {
            throw new FormatException("Invalid coding header.");
        }

        private static void ThrowInvalidOrderOrMissingRecordException()
        {
            throw new FormatException("Invalid records order or missing record(s).");
        }

        private static async Task<byte[]> ReadCodingHeaderBytesAsync(Stream source, int count)
        {
            byte[] bytes = new byte[count];
            int bytesRead = await source.ReadAsync(bytes, 0, count).ConfigureAwait(false);
            if (bytesRead != count)
            {
                ThrowInvalidCodingHeaderException();
            }

            return bytes;
        }

        private static async Task<int> ReadRecordSizeAsync(Stream source)
        {
            byte[] recordSizeBytes = await ReadCodingHeaderBytesAsync(source, RECORD_SIZE_LENGTH).ConfigureAwait(false);

            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(recordSizeBytes);
            }
            uint recordSize = BitConverter.ToUInt32(recordSizeBytes, 0);

            if (recordSize > Int32.MaxValue)
            {
                throw new NotSupportedException($"This implementation doesn't support record size larger than {Int32.MaxValue}.");
            }

            return (int)recordSize;
        }

        private static async Task<byte[]> ReadKeyId(Stream source)
        {
            byte[] keyId = null;

            int keyIdLength = source.ReadByte();

            if (keyIdLength == -1)
            {
                ThrowInvalidCodingHeaderException();
            }
        
            if (keyIdLength > 0)
            {
                keyId = await ReadCodingHeaderBytesAsync(source, keyIdLength).ConfigureAwait(false);
            }

            return keyId;
        }

        private static async Task<CodingHeader> ReadCodingHeaderAsync(Stream source)
        {
            return new CodingHeader
            (
                await ReadCodingHeaderBytesAsync(source, SALT_LENGTH).ConfigureAwait(false),
                await ReadRecordSizeAsync(source).ConfigureAwait(false),
                await ReadKeyId(source).ConfigureAwait(false)
            );
        }

        private static int GetRecordDelimiterIndex(byte[] plainText, int plainTextLength, int maxPlainTextLength)
        {
            int recordDelimiterIndex = -1;
            for (int plaintTextIndex = plainTextLength - 1; plaintTextIndex >= 0; plaintTextIndex--)
            {
                if (plainText[plaintTextIndex] == 0)
                {
                    continue;
                }

                if ((plainText[plaintTextIndex] == RECORD_DELIMITER) || (plainText[plaintTextIndex] == LAST_RECORD_DELIMITER))
                {
                    recordDelimiterIndex = plaintTextIndex;
                }

                break;
            }

            if ((recordDelimiterIndex == -1) || ((plainText[recordDelimiterIndex] == RECORD_DELIMITER) && ((plainTextLength - 1) != maxPlainTextLength)))
            {
                throw new FormatException("Invalid record delimiter.");
            }

            return recordDelimiterIndex;
        }

        private static async Task DecryptContentAsync(Stream source, Stream destination, int recordSize, byte[] contentEncryptionKeyInfoParameterHash, byte[] nonceInfoParameterHash)
        {
            // CEK = FIRST 16 OCTETS OF HMAC-SHA-256(PRK, CEK_INFO)
            KeyParameter key = new KeyParameter(contentEncryptionKeyInfoParameterHash, 0, CONTENT_ENCRYPTION_KEY_LENGTH);
            GcmBlockCipher aes128GcmCipher = new GcmBlockCipher(new AesFastEngine());

            ulong recordSequenceNumber = 0;

            byte[] cipherTextBuffer = new byte[recordSize];
            byte[] plainTextBuffer = new byte[recordSize - RECORD_ENCRYPTION_OVERHEAD_SIZE];
            int maxPlainTextLength = recordSize - RECORD_ENCRYPTION_OVERHEAD_SIZE - RECORD_DELIMITER_SIZE;
            int recordDelimiterIndex = 0;

            do
            {
                int cipherTextLength = await source.ReadAsync(cipherTextBuffer, 0, cipherTextBuffer.Length).ConfigureAwait(false);
                if (cipherTextLength == 0)
                {
                    ThrowInvalidOrderOrMissingRecordException();
                }

                ConfigureAes128GcmCipher(aes128GcmCipher, false, key, nonceInfoParameterHash, recordSequenceNumber++);
                int plainTextLength = Aes128GcmCipherProcessBytes(aes128GcmCipher, cipherTextBuffer, cipherTextLength, plainTextBuffer);
                recordDelimiterIndex = GetRecordDelimiterIndex(plainTextBuffer, plainTextLength, maxPlainTextLength);

                if ((plainTextBuffer[recordDelimiterIndex] == LAST_RECORD_DELIMITER) && (source.ReadByte() != -1))
                {
                    ThrowInvalidOrderOrMissingRecordException();
                }

                await destination.WriteAsync(plainTextBuffer, 0, recordDelimiterIndex).ConfigureAwait(false);
            }
            while (plainTextBuffer[recordDelimiterIndex] != LAST_RECORD_DELIMITER);
        }
        #endregion
    }
}
