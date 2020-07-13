using System;
using System.IO;
using System.Text;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Reflection;
using System.Threading.Tasks;
using Lib.Net.Http.EncryptedContentEncoding.Internals;

namespace Lib.Net.Http.EncryptedContentEncoding
{
    /// <summary>
    /// A class representing an HTTP entity body encoded with aes128gcm encoding.
    /// </summary>
    public sealed class Aes128GcmEncodedContent : HttpContent
    {
        #region Fields
        private const string _mediaType = "application/octet-stream";

        private static MethodInfo _httpContentTryComputeLengthMethodInfo = typeof(HttpContent).GetTypeInfo().GetDeclaredMethod(nameof(TryComputeLength));

        private delegate bool HttpContentTryComputeLengthDelegate(out long length);
        private static Type _httpContentTryComputeLengthDelegateType = typeof(HttpContentTryComputeLengthDelegate);

        private readonly HttpContent _contentToBeEncrypted;
        private readonly byte[] _key;
        private readonly byte[] _keyId;
        private readonly int _recordSize;

        private long? _length;
        #endregion

        #region Constructors
        /// <summary>
        /// Instantiates a new <see cref="Aes128GcmEncodedContent"/>.
        /// </summary>
        /// <param name="contentToBeEncrypted">The content which will be encoded.</param>
        /// <param name="key">The keying material.</param>
        public Aes128GcmEncodedContent(HttpContent contentToBeEncrypted, byte[] key)
            : this(contentToBeEncrypted, key, (byte[])null, Aes128GcmEncoding.DEFAULT_RECORD_SIZE)
        { }

        /// <summary>
        /// Instantiates a new <see cref="Aes128GcmEncodedContent"/>.
        /// </summary>
        /// <param name="contentToBeEncrypted">The content which will be encoded.</param>
        /// <param name="key">The keying material.</param>
        /// <param name="keyId">The keying material identificator.</param>
        public Aes128GcmEncodedContent(HttpContent contentToBeEncrypted, byte[] key, string keyId)
            : this(contentToBeEncrypted, key, keyId, Aes128GcmEncoding.DEFAULT_RECORD_SIZE)
        { }

        /// <summary>
        /// Instantiates a new <see cref="Aes128GcmEncodedContent"/>.
        /// </summary>
        /// <param name="contentToBeEncrypted">The content which will be encoded.</param>
        /// <param name="key">The keying material.</param>
        /// <param name="keyId">The keying material identificator.</param>
        public Aes128GcmEncodedContent(HttpContent contentToBeEncrypted, byte[] key, byte[] keyId)
            : this(contentToBeEncrypted, key, keyId, Aes128GcmEncoding.DEFAULT_RECORD_SIZE)
        { }

        /// <summary>
        /// Instantiates a new <see cref="Aes128GcmEncodedContent"/>.
        /// </summary>
        /// <param name="contentToBeEncrypted">The content which will be encoded.</param>
        /// <param name="key">The keying material.</param>
        /// <param name="recordSize">The record size in octets.</param>
        public Aes128GcmEncodedContent(HttpContent contentToBeEncrypted, byte[] key, int recordSize)
            : this(contentToBeEncrypted, key, (byte[])null, recordSize)
        { }

        /// <summary>
        /// Instantiates a new <see cref="Aes128GcmEncodedContent"/>.
        /// </summary>
        /// <param name="contentToBeEncrypted">The content which will be encoded.</param>
        /// <param name="key">The keying material.</param>
        /// <param name="keyId">The keying material identificator.</param>
        /// <param name="recordSize">The record size in octets.</param>
        public Aes128GcmEncodedContent(HttpContent contentToBeEncrypted, byte[] key, string keyId, int recordSize)
            : this(contentToBeEncrypted, key, Encoding.UTF8.GetBytes(keyId), recordSize)
        { }

        /// <summary>
        /// Instantiates a new <see cref="Aes128GcmEncodedContent"/>.
        /// </summary>
        /// <param name="contentToBeEncrypted">The content which will be encoded.</param>
        /// <param name="key">The keying material.</param>
        /// <param name="keyId">The keying material identificator.</param>
        /// <param name="recordSize">The record size in octets.</param>
        public Aes128GcmEncodedContent(HttpContent contentToBeEncrypted, byte[] key, byte[] keyId, int recordSize)
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
        /// <summary>
        /// Serialize the HTTP content to a stream as an asynchronous operation.
        /// </summary>
        /// <param name="stream">The target stream.</param>
        /// <param name="context">Information about the transport (channel binding token, for example). This parameter may be null.</param>
        /// <returns>The task object representing the asynchronous operation.</returns>
        protected override async Task SerializeToStreamAsync(Stream stream, TransportContext context)
        {
            Stream streamToBeEncrypted = await _contentToBeEncrypted.ReadAsStreamAsync().ConfigureAwait(false);

            await Aes128GcmEncoding.EncodeAsync(streamToBeEncrypted, stream, _key, _keyId, _recordSize).ConfigureAwait(false);
        }

        /// <summary>
        /// Determines whether the HTTP content has a valid length in bytes.
        /// </summary>
        /// <param name="length">The length in bytes of the HTTP content.</param>
        /// <returns>True if length is a valid length, otherwise false.</returns>
        protected override bool TryComputeLength(out long length)
        {
            length = 0;
            bool hasValidLength = false;

            if (_length.HasValue)
            {
                length = _length.Value;
                hasValidLength = true;
            }
            else
            {
                HttpContentTryComputeLengthDelegate httpContentTryComputeLengthDelegateInstance = (HttpContentTryComputeLengthDelegate)_httpContentTryComputeLengthMethodInfo.CreateDelegate(_httpContentTryComputeLengthDelegateType, _contentToBeEncrypted);

                if (httpContentTryComputeLengthDelegateInstance(out long sourceLength))
                {
                    _length = length = Aes128GcmEncoding.ComputeEncodedLength(sourceLength, (byte)(_keyId?.Length ?? 0), _recordSize);
                    hasValidLength = true;
                }
            }

            return hasValidLength;
        }
        #endregion
    }
}
