using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using Lib.Net.Http.EncryptedContentEncoding.Internals;

namespace Lib.Net.Http.EncryptedContentEncoding
{
    public sealed class Aes128GcmEncodedContent : HttpContent
    {
        #region Fields
        private const string _mediaType = "application/octet-stream";

        private readonly HttpContent _contentToBeEncrypted;
        private readonly byte[] _key;
        private readonly string _keyId;
        private readonly int _recordSize;
        #endregion

        #region Constructors
        public Aes128GcmEncodedContent(HttpContent contentToBeEncrypted, byte[] key)
            : this(contentToBeEncrypted, key, null, Aes128GcmEncoding.DEFAULT_RECORD_SIZE)
        { }

        public Aes128GcmEncodedContent(HttpContent contentToBeEncrypted, byte[] key, string keyId)
            : this(contentToBeEncrypted, key, keyId, Aes128GcmEncoding.DEFAULT_RECORD_SIZE)
        { }

        public Aes128GcmEncodedContent(HttpContent contentToBeEncrypted, byte[] key, int recordSize)
            : this(contentToBeEncrypted, key, null, recordSize)
        { }

        public Aes128GcmEncodedContent(HttpContent contentToBeEncrypted, byte[] key, string keyId, int recordSize)
        {
            _contentToBeEncrypted = contentToBeEncrypted;
            _key = key;
            _keyId = keyId;
            _recordSize = recordSize;

            Headers.ContentType = new MediaTypeHeaderValue(_mediaType);
            Headers.ContentEncoding.Add(Constants.ENCRYPTED_CONTENT_ENCODING);
        }
        #endregion

        #region Methods
        protected override async Task SerializeToStreamAsync(Stream stream, TransportContext context)
        {
            Stream streamToBeEncrypted = await _contentToBeEncrypted.ReadAsStreamAsync();

            await Aes128GcmEncoding.EncodeAsync(streamToBeEncrypted, stream, _key, _keyId, _recordSize);
        }

        protected override bool TryComputeLength(out long length)
        {
            length = 0;

            return false;
        }
        #endregion
    }
}
