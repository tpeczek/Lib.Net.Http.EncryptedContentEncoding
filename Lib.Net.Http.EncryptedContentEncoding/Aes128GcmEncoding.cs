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
        public static Task EncodeAsync(Stream source, Stream destination, byte[] key)
        {
            return EncodeAsync(source, destination, null, key, null, DEFAULT_RECORD_SIZE);
        }

        public static Task EncodeAsync(Stream source, Stream destination, byte[] key, string keyId)
        {
            return EncodeAsync(source, destination, null, key, keyId, DEFAULT_RECORD_SIZE);
        }

        public static Task EncodeAsync(Stream source, Stream destination, byte[] key, int recordSize)
        {
            return EncodeAsync(source, destination, null, key, null, recordSize);
        }

        public static Task EncodeAsync(Stream source, Stream destination, byte[] key, string keyId, int recordSize)
        {
            return EncodeAsync(source, destination, null, key, keyId, recordSize);
        }

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

            await WriteCodingHeaderAsync(destination, codingHeader);

            await EncryptContentAsync(source, destination, codingHeader.RecordSize, pseudorandomKey, contentEncryptionKey);
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

            await destination.WriteAsync(codingHeaderBytes, 0, codingHeaderBytes.Length);
        }

        private static async Task<byte[]> GetPlainTextAsync(Stream source, int recordDataSize, byte? peekedByte)
        {
            int readDataSize;
            byte[] plainText = new byte[recordDataSize + 1];

            if (peekedByte.HasValue)
            {
                plainText[0] = peekedByte.Value;
                readDataSize = (await source.ReadAsync(plainText, 1, recordDataSize - 1)) + 1;
            }
            else
            {
                readDataSize = await source.ReadAsync(plainText, 0, recordDataSize);
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
                plainText = await GetPlainTextAsync(source, recordDataSize, (byte?)peekedByte);

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

                await destination.WriteAsync(cipherText, 0, cipherText.Length);
            }
            while (plainText[plainText.Length - 1] != LAST_RECORD_DELIMITER);
        }
        #endregion
    }
}
