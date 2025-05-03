using System;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Runtime.InteropServices;
using HydraLib.Core;

namespace HydraLib.Cryptography
{
    /// <summary>
    /// Provides secure key derivation functionality using .NET's built-in cryptographic implementations.
    /// </summary>
    public static class KeyDerivation
    {
        #region Constants and Default Parameters

        // Default parameters for PBKDF2
        private const int DefaultPbkdf2Iterations = 600000;
        private const int DefaultPbkdf2SaltSize = 16;
        private const int DefaultKeySize = 32; // 256 bits

        #endregion

        #region Key Derivation Methods

        /// <summary>
        /// Derives a key using PBKDF2 with SHA-512.
        /// </summary>
        /// <param name="password">The password bytes</param>
        /// <param name="salt">The salt bytes</param>
        /// <param name="iterations">Number of iterations</param>
        /// <param name="keyLength">Length of derived key in bytes</param>
        /// <returns>The derived key</returns>
        public static byte[] DeriveKey(byte[] password, byte[] salt, int iterations = DefaultPbkdf2Iterations, int keyLength = DefaultKeySize)
        {
            if (password == null || password.Length == 0)
                throw new ArgumentException("Password cannot be null or empty", nameof(password));

            if (salt == null || salt.Length < 8)
                throw new ArgumentException("Salt must be at least 8 bytes", nameof(salt));

            if (iterations < 10000)
                throw new ArgumentException("Iterations should be at least 10,000 for security", nameof(iterations));

            if (keyLength < 16)
                throw new ArgumentException("Key length should be at least 16 bytes (128 bits)", nameof(keyLength));

            // Use .NET's implementation of PBKDF2
            using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA512);
            return pbkdf2.GetBytes(keyLength);
        }

        /// <summary>
        /// Derives a key from a SecureString password.
        /// </summary>
        /// <param name="password">The secure password</param>
        /// <param name="salt">Salt bytes (will be generated if null)</param>
        /// <param name="iterations">Number of iterations</param>
        /// <param name="keyLength">Length of derived key in bytes</param>
        /// <returns>Tuple containing the derived key and the salt used</returns>
        public static (byte[] Key, byte[] Salt) DeriveKey(SecureString password, byte[] salt = null, int iterations = DefaultPbkdf2Iterations, int keyLength = DefaultKeySize)
        {
            if (password == null || password.Length == 0)
                throw new ArgumentException("Password cannot be null or empty", nameof(password));

            // Generate salt if not provided
            if (salt == null || salt.Length < 8)
            {
                salt = GenerateSalt();
            }

            // Convert SecureString to byte array securely
            byte[] passwordBytes = null;

            try
            {
                passwordBytes = SecurityUtilities.SecureStringToUtf8Bytes(password);
                byte[] key = DeriveKey(passwordBytes, salt, iterations, keyLength);
                return (key, salt);
            }
            finally
            {
                // Securely clear the password bytes
                if (passwordBytes != null)
                {
                    SecurityUtilities.SecureZeroMemory(passwordBytes);
                }
            }
        }

        /// <summary>
        /// Derives a key from a plain text password.
        /// </summary>
        /// <param name="password">The password string</param>
        /// <param name="salt">Salt bytes (will be generated if null)</param>
        /// <param name="iterations">Number of iterations</param>
        /// <param name="keyLength">Length of derived key in bytes</param>
        /// <returns>Tuple containing the derived key and the salt used</returns>
        public static (byte[] Key, byte[] Salt) DeriveKey(string password, byte[] salt = null, int iterations = DefaultPbkdf2Iterations, int keyLength = DefaultKeySize)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("Password cannot be null or empty", nameof(password));

            // Generate salt if not provided
            if (salt == null || salt.Length < 8)
            {
                salt = GenerateSalt();
            }

            // Convert string to byte array
            byte[] passwordBytes = null;

            try
            {
                passwordBytes = Encoding.UTF8.GetBytes(password);
                byte[] key = DeriveKey(passwordBytes, salt, iterations, keyLength);
                return (key, salt);
            }
            finally
            {
                // Securely clear the password bytes
                if (passwordBytes != null)
                {
                    SecurityUtilities.SecureZeroMemory(passwordBytes);
                }
            }
        }

        #endregion

        #region Salt Management

        /// <summary>
        /// Generates a cryptographically secure random salt.
        /// </summary>
        /// <param name="size">Size of the salt in bytes</param>
        /// <returns>Random salt bytes</returns>
        public static byte[] GenerateSalt(int size = DefaultPbkdf2SaltSize)
        {
            if (size < 8)
                throw new ArgumentException("Salt size should be at least 8 bytes", nameof(size));

            return SecurityUtilities.GenerateRandomBytes(size);
        }

        #endregion

        #region Key Derivation with Entropy

        /// <summary>
        /// Enhances a key with additional entropy.
        /// </summary>
        /// <param name="baseKey">Base key to enhance</param>
        /// <param name="entropy">Additional entropy bytes</param>
        /// <returns>Enhanced key</returns>
        public static byte[] EnhanceKeyWithEntropy(byte[] baseKey, byte[] entropy)
        {
            if (baseKey == null || baseKey.Length == 0)
                throw new ArgumentException("Base key cannot be null or empty", nameof(baseKey));

            if (entropy == null || entropy.Length == 0)
                return (byte[])baseKey.Clone(); // Return copy of original key

            // Use HMAC to mix entropy into the key
            using var hmac = new HMACSHA512(baseKey);
            byte[] enhancedKey = hmac.ComputeHash(entropy);

            // Ensure the enhanced key is the same length as the base key
            if (enhancedKey.Length != baseKey.Length)
            {
                Array.Resize(ref enhancedKey, baseKey.Length);
            }

            return enhancedKey;
        }

        /// <summary>
        /// Derives a nonce from a key and additional data.
        /// </summary>
        /// <param name="key">The key to use for derivation</param>
        /// <param name="additionalData">Additional data to include in derivation</param>
        /// <param name="nonceSize">Size of nonce to generate in bytes</param>
        /// <returns>Derived nonce</returns>
        public static byte[] DeriveNonce(byte[] key, byte[] additionalData, int nonceSize = 12)
        {
            if (key == null || key.Length == 0)
                throw new ArgumentException("Key cannot be null or empty", nameof(key));

            if (nonceSize < 8)
                throw new ArgumentException("Nonce size should be at least 8 bytes", nameof(nonceSize));

            // Use HMAC to derive a deterministic nonce
            using var hmac = new HMACSHA256(key);

            // Include additional data if provided
            if (additionalData != null && additionalData.Length > 0)
            {
                hmac.TransformBlock(additionalData, 0, additionalData.Length, null, 0);

                // Also include current timestamp to ensure uniqueness
                byte[] timestampBytes = BitConverter.GetBytes(DateTime.UtcNow.Ticks);
                hmac.TransformFinalBlock(timestampBytes, 0, timestampBytes.Length);
            }
            else
            {
                // Use just timestamp if no additional data
                byte[] timestampBytes = BitConverter.GetBytes(DateTime.UtcNow.Ticks);
                hmac.ComputeHash(timestampBytes);
            }

            // Resize hash to nonce size
            byte[] nonce = new byte[nonceSize];
            Array.Copy(hmac.Hash, nonce, Math.Min(hmac.Hash.Length, nonceSize));

            return nonce;
        }

        #endregion

        #region Hardware Detection

        /// <summary>
        /// Determines optimal PBKDF2 iterations based on hardware capabilities.
        /// </summary>
        /// <returns>Recommended iteration count</returns>
        public static int GetOptimalIterations()
        {
            // Test how many iterations can be performed in 250ms
            const int testIterations = 10000;
            const int targetMilliseconds = 250;

            byte[] testPassword = Encoding.UTF8.GetBytes("test_password");
            byte[] testSalt = Encoding.UTF8.GetBytes("test_salt_12345678");

            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            using (var pbkdf2 = new Rfc2898DeriveBytes(testPassword, testSalt, testIterations, HashAlgorithmName.SHA512))
            {
                pbkdf2.GetBytes(32);
            }
            stopwatch.Stop();

            // Calculate iterations to reach target time
            double millisecondsPerIteration = stopwatch.ElapsedMilliseconds / (double)testIterations;
            int recommendedIterations = (int)(targetMilliseconds / millisecondsPerIteration);

            // Ensure minimum security threshold and round to nearest 10000
            recommendedIterations = Math.Max(100000, recommendedIterations);
            recommendedIterations = (recommendedIterations / 10000) * 10000;

            return recommendedIterations;
        }

        #endregion
    }
}