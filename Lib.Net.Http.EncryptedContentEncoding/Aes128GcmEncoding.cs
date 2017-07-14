using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;

namespace Lib.Net.Http.EncryptedContentEncoding
{
    /// <summary>
    /// Provides aes128gcm encoding and decoding routines.
    /// </summary>
    public static class Aes128GcmEncoding
    {
        #region Classes
        private class CodingHeader
        {
            public byte[] Salt { get; set; }

            public int RecordSize { get; set; }

            public string KeyId { get; set; }
        }
        #endregion

        #region Fields
        private const int KEY_LENGTH = 16;

        private const int SALT_INDEX = 0;
        private const int SALT_LENGTH = 16;

        private const int RECORD_OVERHEAD_SIZE = 17;
        private const int MIN_RECORD_SIZE = RECORD_OVERHEAD_SIZE + 1;
        internal const int DEFAULT_RECORD_SIZE = 4096;        
        private const int RECORD_SIZE_INDEX = SALT_INDEX + SALT_LENGTH;
        private const int RECORD_SIZE_LENGTH = 4;

        private const int KEY_ID_LEN_INDEX = RECORD_SIZE_INDEX + RECORD_SIZE_LENGTH;
        private const int KEY_ID_LEN_LENGTH = 1;

        private const int KEY_ID_INDEX = KEY_ID_LEN_INDEX + KEY_ID_LEN_LENGTH;

        private const byte INFO_PARAMETER_DELIMITER = 1;

        private const byte RECORD_DELIMITER = 1;
        private const byte LAST_RECORD_DELIMITER = 2;

        private const string CONTENT_ENCRYPTION_KEY_INFO_PARAMETER_STRING = "Content-Encoding: aes128gcm";
        private const int CONTENT_ENCRYPTION_KEY_LENGTH = 16;

        private const string NONCE_INFO_PARAMETER_STRING = "Content-Encoding: nonce";
        private const int NONCE_LENGTH = 12;

        private static readonly byte[] _contentEncryptionKeyInfoParameter;
        private static readonly byte[] _nonceInfoParameter;
        private static readonly SecureRandom _secureRandom = new SecureRandom();
        #endregion

        #region Constructors
        static Aes128GcmEncoding()
        {
            // CEK_INFO = "Content-Encoding: aes128gcm" || 0x00 || 0x01
            _contentEncryptionKeyInfoParameter = GetInfoParameter(CONTENT_ENCRYPTION_KEY_INFO_PARAMETER_STRING);

            // NONCE_INFO = "Content-Encoding: nonce" || 0x00 || 0x01
            _nonceInfoParameter = GetInfoParameter(NONCE_INFO_PARAMETER_STRING);
        }
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
            return EncodeAsync(source, destination, null, key, null, DEFAULT_RECORD_SIZE);
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
        /// <param name="recordSize">The record size in octets.</param>
        /// <returns>The task object representing the asynchronous operation.</returns>
        public static Task EncodeAsync(Stream source, Stream destination, byte[] key, int recordSize)
        {
            return EncodeAsync(source, destination, null, key, null, recordSize);
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
        /// <param name="salt">The salt.</param>
        /// <param name="key">The keying material.</param>
        /// <param name="keyId">The keying material identificator.</param>
        /// <param name="recordSize">The record size in octets.</param>
        /// <returns>The task object representing the asynchronous operation.</returns>
        public static async Task EncodeAsync(Stream source, Stream destination, byte[] salt, byte[] key, string keyId, int recordSize)
        {
            ValidateEncodeParameters(source, destination, key, recordSize);

            CodingHeader codingHeader = new CodingHeader
            {
                Salt = CoalesceSalt(salt),
                RecordSize = recordSize,
                KeyId = keyId
            };

            // PRK = HMAC-SHA-256(salt, IKM)
            byte[] pseudorandomKey = HmacSha256(codingHeader.Salt, key);
            byte[] contentEncryptionKey = GetContentEncryptionKey(pseudorandomKey);

            await WriteCodingHeaderAsync(destination, codingHeader).ConfigureAwait(false);

            await EncryptContentAsync(source, destination, codingHeader.RecordSize, pseudorandomKey, contentEncryptionKey).ConfigureAwait(false);
        }

        /// <summary>
        /// Decodes source stream into destionation stream as an asynchronous operation.
        /// </summary>
        /// <param name="source">The source stream.</param>
        /// <param name="destination">The destionation stream.</param>
        /// <param name="keyLocator">The function which is able to locate the keying material based on the keying material identificator.</param>
        /// <returns>The task object representing the asynchronous operation.</returns>
        public static async Task DecodeAsync(Stream source, Stream destination, Func<string, byte[]> keyLocator)
        {
            ValidateDecodeParameters(source, destination, keyLocator);

            CodingHeader codingHeader = await ReadCodingHeaderAsync(source).ConfigureAwait(false);

            byte[] pseudorandomKey = HmacSha256(codingHeader.Salt, keyLocator(codingHeader.KeyId));
            byte[] contentEncryptionKey = GetContentEncryptionKey(pseudorandomKey);

            await DecryptContentAsync(source, destination, codingHeader.RecordSize, pseudorandomKey, contentEncryptionKey).ConfigureAwait(false);
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
                hash = hasher.ComputeHash(value);
            }

            return hash;
        }

        private static byte[] GetContentEncryptionKey(byte[] pseudorandomKey)
        {
            // CEK = FIRST 16 OCTETS OF HMAC-SHA-256(PRK, CEK_INFO)
            byte[] contentEncryptionKey = HmacSha256(pseudorandomKey, _contentEncryptionKeyInfoParameter);
            Array.Resize(ref contentEncryptionKey, CONTENT_ENCRYPTION_KEY_LENGTH);

            return contentEncryptionKey;
        }

        private static byte[] GetNonce(byte[] pseudorandomKey, ulong recordSequenceNumber)
        {
            // NONCE = FIRST 12 OCTETS OF HMAC-SHA-256(PRK, NONCE_INFO) XOR SEQ
            byte[] nonce = HmacSha256(pseudorandomKey, _nonceInfoParameter);
            Array.Resize(ref nonce, NONCE_LENGTH);

            byte[] recordSequenceNumberBytes = BitConverter.GetBytes(recordSequenceNumber);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(recordSequenceNumberBytes);
            }
            int leadingNullBytesCount = NONCE_LENGTH - recordSequenceNumberBytes.Length;

            for (int i = 0; i < leadingNullBytesCount; i++)
            {
                nonce[i] = (byte)(nonce[i] ^ 0);
            }

            for (int i = 0; i < recordSequenceNumberBytes.Length; i++)
            {
                nonce[leadingNullBytesCount + i] = (byte)(nonce[leadingNullBytesCount + i] ^ recordSequenceNumberBytes[i]);
            }

            return nonce;
        }

        private static void ConfigureAes128GcmCipher(GcmBlockCipher aes128GcmCipher, bool forEncryption, byte[] pseudorandomKey, byte[] contentEncryptionKey, ulong recordSequenceNumber)
        {
            aes128GcmCipher.Reset();
            AeadParameters aes128GcmParameters = new AeadParameters(new KeyParameter(contentEncryptionKey), 128, GetNonce(pseudorandomKey, recordSequenceNumber));
            aes128GcmCipher.Init(forEncryption, aes128GcmParameters);
        }

        private static byte[] Aes128GcmCipherProcessBytes(GcmBlockCipher aes128GcmCipher, byte[] bytes, int bytesToProcessLength)
        {
            byte[] processedBytes = new byte[aes128GcmCipher.GetOutputSize(bytesToProcessLength)];
            int lenght = aes128GcmCipher.ProcessBytes(bytes, 0, bytesToProcessLength, processedBytes, 0);
            aes128GcmCipher.DoFinal(processedBytes, lenght);

            return processedBytes;
        }
        #endregion

        #region Encode Private Methods
        private static void ValidateEncodeParameters(Stream source, Stream destination, byte[] key, int recordSize)
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

            if (key.Length != KEY_LENGTH)
            {
                throw new ArgumentException($" The '{nameof(key)}' parameter must be {KEY_LENGTH} octets long.", nameof(key));
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

        private static byte[] GetKeyIdBytes(string keyId)
        {
            byte[] keyIdBytes = String.IsNullOrEmpty(keyId) ? new byte[0] : Encoding.UTF8.GetBytes(keyId);
            if (keyIdBytes.Length > Byte.MaxValue)
            {
                throw new ArgumentException($"The '{nameof(keyId)}' parameter is too long.", nameof(keyId));
            }

            return keyIdBytes;
        }

        private static byte[] GetRecordSizeBytes(int recordSize)
        {
            byte[] recordSizeBytes = BitConverter.GetBytes(recordSize);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(recordSizeBytes);
            }

            return recordSizeBytes;
        }

        private static async Task WriteCodingHeaderAsync(Stream destination, CodingHeader codingHeader)
        {
            //+----------+---------------+-------------+-----------------+
            //| SALT(16) | RECORDSIZE(4) | KEYIDLEN(1) | KEYID(KEYIDLEN) |
            //+----------+---------------+-------------+-----------------+

            byte[] keyIdBytes = GetKeyIdBytes(codingHeader.KeyId);
            byte[] recordSizeBytes = GetRecordSizeBytes(codingHeader.RecordSize);

            byte[] codingHeaderBytes = new byte[SALT_LENGTH + RECORD_SIZE_LENGTH + KEY_ID_LEN_LENGTH + keyIdBytes.Length];

            codingHeader.Salt.CopyTo(codingHeaderBytes, SALT_INDEX);
            recordSizeBytes.CopyTo(codingHeaderBytes, RECORD_SIZE_INDEX);
            codingHeaderBytes[KEY_ID_LEN_INDEX] = (byte)keyIdBytes.Length;
            keyIdBytes.CopyTo(codingHeaderBytes, KEY_ID_INDEX);

            await destination.WriteAsync(codingHeaderBytes, 0, codingHeaderBytes.Length).ConfigureAwait(false);
        }

        private static async Task<byte[]> GetPlainTextAsync(Stream source, int recordDataSize, byte? peekedByte)
        {
            int readDataSize;
            byte[] plainText = new byte[recordDataSize + 1];

            if (peekedByte.HasValue)
            {
                plainText[0] = peekedByte.Value;
                readDataSize = (await source.ReadAsync(plainText, 1, recordDataSize - 1).ConfigureAwait(false)) + 1;
            }
            else
            {
                readDataSize = await source.ReadAsync(plainText, 0, recordDataSize).ConfigureAwait(false);
            }

            if (readDataSize == recordDataSize)
            {
                plainText[plainText.Length - 1] = RECORD_DELIMITER;
            }
            else
            {
                Array.Resize(ref plainText, readDataSize + 1);
                plainText[plainText.Length - 1] = LAST_RECORD_DELIMITER;
            }

            return plainText;
        }

        private static async Task EncryptContentAsync(Stream source, Stream destination, int recordSize, byte[] pseudorandomKey, byte[] contentEncryptionKey)
        {
            GcmBlockCipher aes128GcmCipher = new GcmBlockCipher(new AesFastEngine());

            ulong recordSequenceNumber = 0;
            int recordDataSize = recordSize - RECORD_OVERHEAD_SIZE;

            byte[] plainText = null;
            int? peekedByte = null;

            do
            {
                plainText = await GetPlainTextAsync(source, recordDataSize, (byte?)peekedByte).ConfigureAwait(false);

                if (plainText[plainText.Length - 1] != 2)
                {
                    peekedByte = source.ReadByte();
                    if (peekedByte == -1)
                    {
                        plainText[plainText.Length - 1] = LAST_RECORD_DELIMITER;
                    }
                }

                ConfigureAes128GcmCipher(aes128GcmCipher, true, pseudorandomKey, contentEncryptionKey, recordSequenceNumber++);
                byte[] cipherText = Aes128GcmCipherProcessBytes(aes128GcmCipher, plainText, plainText.Length);

                await destination.WriteAsync(cipherText, 0, cipherText.Length).ConfigureAwait(false);
            }
            while (plainText[plainText.Length - 1] != LAST_RECORD_DELIMITER);
        }
        #endregion

        #region Decode Private Methods
        private static void ValidateDecodeParameters(Stream source, Stream destination, Func<string, byte[]> keyLocator)
        {
            if (source == null)
            {
                throw new ArgumentNullException(nameof(source));
            }

            if (destination == null)
            {
                throw new ArgumentNullException(nameof(destination));
            }

            if (keyLocator == null)
            {
                throw new ArgumentNullException(nameof(keyLocator));
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

        private static async Task<string> ReadKeyId(Stream source)
        {
            string keyId = null;

            int keyIdLength = source.ReadByte();

            if (keyIdLength == -1)
            {
                ThrowInvalidCodingHeaderException();
            }
        
            if (keyIdLength > 0)
            {
                byte[] keyIdBytes = await ReadCodingHeaderBytesAsync(source, keyIdLength).ConfigureAwait(false);
                keyId = Encoding.UTF8.GetString(keyIdBytes);
            }

            return keyId;
        }

        private static async Task<CodingHeader> ReadCodingHeaderAsync(Stream source)
        {
            return new CodingHeader
            {
                Salt = await ReadCodingHeaderBytesAsync(source, SALT_LENGTH).ConfigureAwait(false),
                RecordSize = await ReadRecordSizeAsync(source).ConfigureAwait(false),
                KeyId = await ReadKeyId(source).ConfigureAwait(false)
            };
        }

        private static int GetRecordDelimiterIndex(byte[] plainText, int recordDataSize)
        {
            int recordDelimiterIndex = -1;
            for (int plaintTextIndex = plainText.Length - 1; plaintTextIndex >= 0; plaintTextIndex--)
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

            if ((recordDelimiterIndex == -1) || ((plainText[recordDelimiterIndex] == RECORD_DELIMITER) && ((plainText.Length -1) != recordDataSize)))
            {
                throw new FormatException("Invalid record delimiter.");
            }

            return recordDelimiterIndex;
        }

        private static async Task DecryptContentAsync(Stream source, Stream destination, int recordSize, byte[] pseudorandomKey, byte[] contentEncryptionKey)
        {
            GcmBlockCipher aes128GcmCipher = new GcmBlockCipher(new AesFastEngine());

            ulong recordSequenceNumber = 0;

            byte[] cipherText = new byte[recordSize];
            byte[] plainText = null;
            int recordDataSize = recordSize - RECORD_OVERHEAD_SIZE;
            int recordDelimiterIndex = 0;

            do
            {
                int cipherTextLength = await source.ReadAsync(cipherText, 0, cipherText.Length).ConfigureAwait(false);
                if (cipherTextLength == 0)
                {
                    ThrowInvalidOrderOrMissingRecordException();
                }

                ConfigureAes128GcmCipher(aes128GcmCipher, false, pseudorandomKey, contentEncryptionKey, recordSequenceNumber++);
                plainText = Aes128GcmCipherProcessBytes(aes128GcmCipher, cipherText, cipherTextLength);
                recordDelimiterIndex = GetRecordDelimiterIndex(plainText, recordDataSize);

                if ((plainText[recordDelimiterIndex] == LAST_RECORD_DELIMITER) && (source.ReadByte() != -1))
                {
                    ThrowInvalidOrderOrMissingRecordException();
                }

                await destination.WriteAsync(plainText, 0, recordDelimiterIndex).ConfigureAwait(false);
            }
            while (plainText[recordDelimiterIndex] != LAST_RECORD_DELIMITER);
        }
        #endregion
    }
}
