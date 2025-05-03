using System;
using System.IO;
using System.IO.Compression;
using System.Threading.Tasks;

namespace HydraLib.Core
{
    /// <summary>
    /// Provides compression and decompression functionality for the multi-layer encryption system.
    /// Uses built-in .NET compression capabilities.
    /// </summary>
    public static class CompressionProvider
    {
        /// <summary>
        /// Defines available compression algorithms
        /// </summary>
        public enum CompressionAlgorithm
        {
            /// <summary>
            /// No compression
            /// </summary>
            None = 0,

            /// <summary>
            /// GZIP compression
            /// </summary>
            GZip = 1,

            /// <summary>
            /// Deflate compression
            /// </summary>
            Deflate = 2,

            /// <summary>
            /// Brotli compression
            /// </summary>
            Brotli = 3
        }

        // Signature header to identify compressed data
        private static readonly byte[] CompressionSignature = { 0xC0, 0xDE, 0x10, 0x57 };

        #region Compression Methods

        /// <summary>
        /// Compresses data using the specified algorithm.
        /// </summary>
        /// <param name="data">Data to compress</param>
        /// <param name="algorithm">Compression algorithm to use</param>
        /// <param name="level">Compression level</param>
        /// <returns>Compressed data with algorithm signature</returns>
        public static byte[] Compress(byte[] data, CompressionAlgorithm algorithm = CompressionAlgorithm.GZip, CompressionLevel level = CompressionLevel.Optimal)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));

            // Skip compression for very small data
            if (data.Length < 100 || algorithm == CompressionAlgorithm.None)
            {
                return CreateCompressedDataWithHeader(data, CompressionAlgorithm.None);
            }

            using var outputStream = new MemoryStream();

            // Write compression header with algorithm info
            outputStream.Write(CompressionSignature, 0, CompressionSignature.Length);
            outputStream.WriteByte((byte)algorithm);

            // Apply compression based on selected algorithm
            using (Stream compressionStream = CreateCompressionStream(outputStream, algorithm, level))
            {
                compressionStream.Write(data, 0, data.Length);
            }

            return outputStream.ToArray();
        }

        /// <summary>
        /// Compresses a stream using the specified algorithm.
        /// </summary>
        /// <param name="inputStream">Stream to compress</param>
        /// <param name="outputStream">Stream to write compressed data to</param>
        /// <param name="algorithm">Compression algorithm to use</param>
        /// <param name="level">Compression level</param>
        /// <returns>True if compression was applied, false if skipped</returns>
        public static async Task<bool> CompressAsync(Stream inputStream, Stream outputStream,
            CompressionAlgorithm algorithm = CompressionAlgorithm.GZip,
            CompressionLevel level = CompressionLevel.Optimal)
        {
            if (inputStream == null)
                throw new ArgumentNullException(nameof(inputStream));

            if (outputStream == null)
                throw new ArgumentNullException(nameof(outputStream));

            if (!inputStream.CanRead)
                throw new ArgumentException("Input stream must be readable", nameof(inputStream));

            if (!outputStream.CanWrite)
                throw new ArgumentException("Output stream must be writable", nameof(outputStream));

            // Write compression header with algorithm info
            await outputStream.WriteAsync(CompressionSignature, 0, CompressionSignature.Length);
            await outputStream.WriteAsync(new byte[] { (byte)algorithm }, 0, 1);

            // Skip compression for "None" algorithm
            if (algorithm == CompressionAlgorithm.None)
            {
                await inputStream.CopyToAsync(outputStream);
                return false;
            }

            // Apply compression
            using (Stream compressionStream = CreateCompressionStream(outputStream, algorithm, level))
            {
                await inputStream.CopyToAsync(compressionStream);
            }

            return true;
        }

        /// <summary>
        /// Creates an appropriate compression stream based on the selected algorithm.
        /// </summary>
        private static Stream CreateCompressionStream(Stream outputStream, CompressionAlgorithm algorithm, CompressionLevel level)
        {
            return algorithm switch
            {
                CompressionAlgorithm.GZip => new GZipStream(outputStream, level, true),
                CompressionAlgorithm.Deflate => new DeflateStream(outputStream, level, true),
                CompressionAlgorithm.Brotli => new BrotliStream(outputStream, level, true),
                _ => throw new ArgumentException($"Unsupported compression algorithm: {algorithm}")
            };
        }

        /// <summary>
        /// Creates compressed data with a header.
        /// </summary>
        private static byte[] CreateCompressedDataWithHeader(byte[] data, CompressionAlgorithm algorithm)
        {
            // Format: Signature (4 bytes) + Algorithm (1 byte) + Data
            byte[] result = new byte[CompressionSignature.Length + 1 + data.Length];

            // Copy signature
            Buffer.BlockCopy(CompressionSignature, 0, result, 0, CompressionSignature.Length);

            // Set algorithm
            result[CompressionSignature.Length] = (byte)algorithm;

            // Copy data
            Buffer.BlockCopy(data, 0, result, CompressionSignature.Length + 1, data.Length);

            return result;
        }

        #endregion

        #region Decompression Methods

        /// <summary>
        /// Decompresses data compressed with the Compress method.
        /// </summary>
        /// <param name="compressedData">Compressed data with algorithm signature</param>
        /// <returns>Decompressed data</returns>
        public static byte[] Decompress(byte[] compressedData)
        {
            if (compressedData == null)
                throw new ArgumentNullException(nameof(compressedData));

            // Check minimum length for header
            if (compressedData.Length < CompressionSignature.Length + 1)
                throw new ArgumentException("Data is too short to be valid compressed data", nameof(compressedData));

            // Verify signature
            for (int i = 0; i < CompressionSignature.Length; i++)
            {
                if (compressedData[i] != CompressionSignature[i])
                    throw new ArgumentException("Invalid compression signature", nameof(compressedData));
            }

            // Get algorithm
            CompressionAlgorithm algorithm = (CompressionAlgorithm)compressedData[CompressionSignature.Length];

            // Handle uncompressed data
            if (algorithm == CompressionAlgorithm.None)
            {
                byte[] result = new byte[compressedData.Length - (CompressionSignature.Length + 1)];
                Buffer.BlockCopy(compressedData, CompressionSignature.Length + 1, result, 0, result.Length);
                return result;
            }

            // Decompress based on algorithm
            using var inputStream = new MemoryStream(compressedData, CompressionSignature.Length + 1,
                compressedData.Length - (CompressionSignature.Length + 1));

            using var outputStream = new MemoryStream();
            using (Stream decompressionStream = CreateDecompressionStream(inputStream, algorithm))
            {
                decompressionStream.CopyTo(outputStream);
            }

            return outputStream.ToArray();
        }

        /// <summary>
        /// Decompresses a stream compressed with the CompressAsync method.
        /// </summary>
        /// <param name="inputStream">Stream containing compressed data</param>
        /// <param name="outputStream">Stream to write decompressed data to</param>
        /// <returns>True if decompression was applied, false if data was not compressed</returns>
        public static async Task<bool> DecompressAsync(Stream inputStream, Stream outputStream)
        {
            if (inputStream == null)
                throw new ArgumentNullException(nameof(inputStream));

            if (outputStream == null)
                throw new ArgumentNullException(nameof(outputStream));

            if (!inputStream.CanRead)
                throw new ArgumentException("Input stream must be readable", nameof(inputStream));

            if (!outputStream.CanWrite)
                throw new ArgumentException("Output stream must be writable", nameof(outputStream));

            // Read and verify signature
            byte[] signature = new byte[CompressionSignature.Length];
            int bytesRead = await inputStream.ReadAsync(signature, 0, signature.Length);

            if (bytesRead != signature.Length)
                throw new InvalidDataException("Could not read compression signature");

            for (int i = 0; i < CompressionSignature.Length; i++)
            {
                if (signature[i] != CompressionSignature[i])
                    throw new InvalidDataException("Invalid compression signature");
            }

            // Read algorithm
            int algorithmByte = inputStream.ReadByte();
            if (algorithmByte == -1)
                throw new InvalidDataException("Could not read compression algorithm");

            CompressionAlgorithm algorithm = (CompressionAlgorithm)algorithmByte;

            // Handle uncompressed data
            if (algorithm == CompressionAlgorithm.None)
            {
                await inputStream.CopyToAsync(outputStream);
                return false;
            }

            // Decompress based on algorithm
            using (Stream decompressionStream = CreateDecompressionStream(inputStream, algorithm))
            {
                await decompressionStream.CopyToAsync(outputStream);
            }

            return true;
        }

        /// <summary>
        /// Creates an appropriate decompression stream based on the selected algorithm.
        /// </summary>
        private static Stream CreateDecompressionStream(Stream inputStream, CompressionAlgorithm algorithm)
        {
            return algorithm switch
            {
                CompressionAlgorithm.GZip => new GZipStream(inputStream, CompressionMode.Decompress, true),
                CompressionAlgorithm.Deflate => new DeflateStream(inputStream, CompressionMode.Decompress, true),
                CompressionAlgorithm.Brotli => new BrotliStream(inputStream, CompressionMode.Decompress, true),
                _ => throw new ArgumentException($"Unsupported compression algorithm: {algorithm}")
            };
        }

        #endregion

        #region Utility Methods

        /// <summary>
        /// Checks if data is compressed by this provider.
        /// </summary>
        /// <param name="data">Data to check</param>
        /// <returns>True if data has a valid compression signature, false otherwise</returns>
        public static bool IsCompressed(byte[] data)
        {
            if (data == null || data.Length < CompressionSignature.Length)
                return false;

            for (int i = 0; i < CompressionSignature.Length; i++)
            {
                if (data[i] != CompressionSignature[i])
                    return false;
            }

            return true;
        }

        /// <summary>
        /// Gets the compression algorithm used for the data, if it is compressed.
        /// </summary>
        /// <param name="data">Potentially compressed data</param>
        /// <param name="algorithm">Output parameter for the detected algorithm</param>
        /// <returns>True if data is compressed and algorithm detected, false otherwise</returns>
        public static bool TryGetCompressionAlgorithm(byte[] data, out CompressionAlgorithm algorithm)
        {
            algorithm = CompressionAlgorithm.None;

            if (!IsCompressed(data) || data.Length < CompressionSignature.Length + 1)
                return false;

            algorithm = (CompressionAlgorithm)data[CompressionSignature.Length];
            return Enum.IsDefined(typeof(CompressionAlgorithm), algorithm);
        }

        /// <summary>
        /// Estimates the compression ratio that could be achieved for the specified data.
        /// Uses a small sample to predict compression effectiveness.
        /// </summary>
        /// <param name="data">Data to evaluate</param>
        /// <param name="algorithm">Compression algorithm to use</param>
        /// <returns>Estimated compression ratio (1.0 = no compression, 2.0 = 50% size reduction)</returns>
        public static double EstimateCompressionRatio(byte[] data, CompressionAlgorithm algorithm = CompressionAlgorithm.GZip)
        {
            if (data == null || data.Length < 1000 || algorithm == CompressionAlgorithm.None)
                return 1.0; // No compression or too small to be worth compressing

            // Take a sample of up to 8KB to estimate compression ratio
            int sampleSize = Math.Min(8192, data.Length);
            byte[] sample = new byte[sampleSize];
            Buffer.BlockCopy(data, 0, sample, 0, sampleSize);

            byte[] compressed = Compress(sample, algorithm);

            // Calculate ratio excluding the header size
            int compressedDataSize = compressed.Length - (CompressionSignature.Length + 1);
            return (double)sampleSize / compressedDataSize;
        }

        /// <summary>
        /// Recommends whether to compress data based on its content.
        /// </summary>
        /// <param name="data">Data to evaluate</param>
        /// <returns>Best compression algorithm to use, or None if compression is not recommended</returns>
        public static CompressionAlgorithm RecommendCompression(byte[] data)
        {
            if (data == null || data.Length < 1000)
                return CompressionAlgorithm.None; // Too small to be worth compressing

            // Check data entropy to determine if compression is likely to be effective
            double entropy = CalculateEntropy(data);

            // High entropy data (e.g., already compressed or encrypted) doesn't benefit from compression
            if (entropy > 7.5) // Near maximum entropy for 8-bit values
                return CompressionAlgorithm.None;

            // For text or low-entropy data, different algorithms may perform better
            if (entropy < 4.0)
                return CompressionAlgorithm.Deflate; // Good for simple text
            else if (entropy < 6.0)
                return CompressionAlgorithm.GZip; // Good balance for mixed content
            else
                return CompressionAlgorithm.Brotli; // Better for moderate entropy content
        }

        /// <summary>
        /// Calculates Shannon entropy of data to determine compressibility.
        /// </summary>
        private static double CalculateEntropy(byte[] data)
        {
            if (data == null || data.Length == 0)
                return 0;

            // Count occurrences of each byte value
            int[] counts = new int[256];
            foreach (byte b in data)
            {
                counts[b]++;
            }

            // Calculate entropy using Shannon formula
            double entropy = 0;
            double sampleSize = data.Length;

            for (int i = 0; i < 256; i++)
            {
                if (counts[i] > 0)
                {
                    double probability = counts[i] / sampleSize;
                    entropy -= probability * Math.Log(probability, 2);
                }
            }

            return entropy;
        }

        #endregion
    }
}