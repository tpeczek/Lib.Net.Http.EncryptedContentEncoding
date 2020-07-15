namespace Lib.Net.Http.EncryptedContentEncoding.Internals
{
    internal static class Aes128GcmHelper
    {
        internal const int CONTENT_ENCRYPTION_KEY_LENGTH = 16;

        private const int NONCE_LENGTH = 12;

        internal static byte[] XorNonce(byte[] nonceInfoParameterHash, ulong recordSequenceNumber)
        {
            // NONCE = FIRST 12 OCTETS OF HMAC-SHA-256(PRK, NONCE_INFO) XOR SEQ
            byte[] nonce = new byte[NONCE_LENGTH];

            nonce[0] = (byte)(nonceInfoParameterHash[0] ^ 0);
            nonce[1] = (byte)(nonceInfoParameterHash[1] ^ 0);
            nonce[2] = (byte)(nonceInfoParameterHash[2] ^ 0);
            nonce[3] = (byte)(nonceInfoParameterHash[3] ^ 0);
            nonce[4] = (byte)(nonceInfoParameterHash[4] ^ (byte)(recordSequenceNumber >> 56));
            nonce[5] = (byte)(nonceInfoParameterHash[5] ^ (byte)(recordSequenceNumber >> 48));
            nonce[6] = (byte)(nonceInfoParameterHash[6] ^ (byte)(recordSequenceNumber >> 40));
            nonce[7] = (byte)(nonceInfoParameterHash[7] ^ (byte)(recordSequenceNumber >> 32));
            nonce[8] = (byte)(nonceInfoParameterHash[8] ^ (byte)(recordSequenceNumber >> 24));
            nonce[9] = (byte)(nonceInfoParameterHash[9] ^ (byte)(recordSequenceNumber >> 16));
            nonce[10] = (byte)(nonceInfoParameterHash[10] ^ (byte)(recordSequenceNumber >> 8));
            nonce[11] = (byte)(nonceInfoParameterHash[11] ^ (byte)(recordSequenceNumber));

            return nonce;
        }
    }
}
