using System;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Runtime.CompilerServices;
using System.Text;

namespace HydraLib.Core
{
    /// <summary>
    /// Provides core security utilities for the multi-layer encryption system.
    /// Handles secure memory operations, random generation, and password validation.
    /// </summary>
    public static class SecurityUtilities
    {
        #region Secure Memory Operations

        /// <summary>
        /// Securely clears the contents of a byte array by overwriting with zeros.
        /// </summary>
        /// <param name="data">The byte array to clear</param>
        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        public static void SecureZeroMemory(byte[] data)
        {
            if (data == null)
                return;

            Array.Clear(data, 0, data.Length);
        }

        /// <summary>
        /// Securely clears the contents of a span of memory by overwriting with zeros.
        /// </summary>
        /// <param name="span">The span to clear</param>
        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        public static void SecureZeroMemory(Span<byte> span)
        {
            span.Fill(0);
        }

        /// <summary>
        /// Converts a SecureString to a byte array, then securely clears the temporary buffer.
        /// </summary>
        /// <param name="secureString">The SecureString to convert</param>
        /// <returns>Byte array containing the UTF-8 encoded string</returns>
        public static byte[] SecureStringToUtf8Bytes(SecureString secureString)
        {
            if (secureString == null || secureString.Length == 0)
                return Array.Empty<byte>();

            IntPtr unmanagedString = IntPtr.Zero;
            try
            {
                unmanagedString = Marshal.SecureStringToGlobalAllocUnicode(secureString);
                string insecureString = Marshal.PtrToStringUni(unmanagedString);
                return Encoding.UTF8.GetBytes(insecureString);
            }
            finally
            {
                if (unmanagedString != IntPtr.Zero)
                {
                    Marshal.ZeroFreeGlobalAllocUnicode(unmanagedString);
                }
            }
        }

        #endregion

        #region Secure Random Generation

        /// <summary>
        /// Generates a cryptographically secure random byte array.
        /// </summary>
        /// <param name="length">Number of random bytes to generate</param>
        /// <returns>Array filled with random bytes</returns>
        public static byte[] GenerateRandomBytes(int length)
        {
            if (length <= 0)
                throw new ArgumentOutOfRangeException(nameof(length), "Length must be positive");

            var bytes = new byte[length];
            RandomNumberGenerator.Fill(bytes);
            return bytes;
        }

        /// <summary>
        /// Generates a cryptographically secure random integer within the specified range.
        /// </summary>
        /// <param name="minValue">Minimum value (inclusive)</param>
        /// <param name="maxValue">Maximum value (exclusive)</param>
        /// <returns>Random integer within the specified range</returns>
        public static int GenerateRandomInt(int minValue, int maxValue)
        {
            if (minValue >= maxValue)
                throw new ArgumentException("minValue must be less than maxValue");

            // Use .NET's secure random implementation
            return RandomNumberGenerator.GetInt32(minValue, maxValue);
        }

        /// <summary>
        /// Generates a strong password with guaranteed complexity.
        /// </summary>
        /// <param name="length">Length of password to generate</param>
        /// <param name="includeSpecial">Whether to include special characters</param>
        /// <returns>A strong random password</returns>
        public static string GenerateStrongPassword(int length, bool includeSpecial = true)
        {
            if (length < 12)
                throw new ArgumentException("Password length should be at least 12 characters");

            const string uppercase = "ABCDEFGHJKLMNPQRSTUVWXYZ"; // Excluded O and I for clarity
            const string lowercase = "abcdefghijkmnopqrstuvwxyz"; // Excluded l for clarity
            const string digits = "23456789"; // Excluded 0 and 1 for clarity
            const string special = "!@#$%^&*()_+-=[]{}|;:,./<>?";

            string charSet = uppercase + lowercase + digits;
            if (includeSpecial)
                charSet += special;

            var passwordChars = new char[length];

            // Ensure at least one of each required type for complexity
            passwordChars[0] = uppercase[RandomNumberGenerator.GetInt32(0, uppercase.Length)];
            passwordChars[1] = lowercase[RandomNumberGenerator.GetInt32(0, lowercase.Length)];
            passwordChars[2] = digits[RandomNumberGenerator.GetInt32(0, digits.Length)];

            if (includeSpecial)
                passwordChars[3] = special[RandomNumberGenerator.GetInt32(0, special.Length)];

            // Fill the rest randomly
            for (int i = includeSpecial ? 4 : 3; i < length; i++)
            {
                passwordChars[i] = charSet[RandomNumberGenerator.GetInt32(0, charSet.Length)];
            }

            // Shuffle the result
            for (int i = 0; i < length; i++)
            {
                int swapIndex = RandomNumberGenerator.GetInt32(0, length);
                (passwordChars[i], passwordChars[swapIndex]) = (passwordChars[swapIndex], passwordChars[i]);
            }

            return new string(passwordChars);
        }

        #endregion

        #region Password Validation

        /// <summary>
        /// Calculates a password strength score (0-100).
        /// </summary>
        /// <param name="password">Password to evaluate</param>
        /// <returns>Password strength score (0-100)</returns>
        public static int CalculatePasswordStrength(string password)
        {
            if (string.IsNullOrEmpty(password))
                return 0;

            int score = 0;
            bool hasLower = false, hasUpper = false, hasDigit = false, hasSpecial = false;

            foreach (char c in password)
            {
                if (char.IsLower(c)) hasLower = true;
                else if (char.IsUpper(c)) hasUpper = true;
                else if (char.IsDigit(c)) hasDigit = true;
                else hasSpecial = true;
            }

            // Baseline based on length
            if (password.Length >= 16) score += 40;
            else if (password.Length >= 12) score += 30;
            else if (password.Length >= 8) score += 20;
            else score += 10;

            // Add for character diversity
            if (hasLower) score += 10;
            if (hasUpper) score += 15;
            if (hasDigit) score += 15;
            if (hasSpecial) score += 20;

            // Penalize simple patterns
            if (password.Length > 2)
            {
                bool hasRepeat = false;
                for (int i = 0; i < password.Length - 2; i++)
                {
                    if (password[i] == password[i + 1] && password[i] == password[i + 2])
                    {
                        hasRepeat = true;
                        break;
                    }
                }

                if (hasRepeat) score -= 15;
            }

            return Math.Clamp(score, 0, 100);
        }

        /// <summary>
        /// Checks if a password meets minimum complexity requirements.
        /// </summary>
        /// <param name="password">Password to validate</param>
        /// <param name="minScore">Minimum strength score required (0-100)</param>
        /// <returns>True if the password is sufficiently strong, false otherwise</returns>
        public static bool IsPasswordStrong(string password, int minScore = 60)
        {
            return CalculatePasswordStrength(password) >= minScore;
        }

        #endregion

        #region Time-Safe Operations

        /// <summary>
        /// Compares two byte arrays in constant time to prevent timing attacks.
        /// </summary>
        /// <param name="a">First byte array</param>
        /// <param name="b">Second byte array</param>
        /// <returns>True if arrays are equal, false otherwise</returns>
        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        public static bool ConstantTimeEquals(byte[] a, byte[] b)
        {
            if (a == null || b == null)
                return false;

            if (a.Length != b.Length)
                return false;

            // Use .NET's CryptographicOperations for constant-time comparison
            return CryptographicOperations.FixedTimeEquals(a, b);
        }

        /// <summary>
        /// Compares two spans in constant time to prevent timing attacks.
        /// </summary>
        /// <param name="a">First span</param>
        /// <param name="b">Second span</param>
        /// <returns>True if spans are equal, false otherwise</returns>
        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        public static bool ConstantTimeEquals(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
        {
            // Use .NET's CryptographicOperations for constant-time comparison
            return a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
        }

        #endregion

        #region Entropy Collection

        /// <summary>
        /// Collects entropy from system and environment sources.
        /// </summary>
        /// <param name="size">Size of entropy buffer to generate in bytes</param>
        /// <returns>Entropy bytes</returns>
        public static byte[] CollectSystemEntropy(int size = 32)
        {
            if (size <= 0)
                throw new ArgumentOutOfRangeException(nameof(size), "Size must be positive");

            // Create a buffer for entropy
            byte[] entropy = new byte[size];

            // Fill with cryptographically secure random data as base
            RandomNumberGenerator.Fill(entropy);

            // Mix in additional entropy sources using hashing
            using (var hash = SHA256.Create())
            {
                // Add current date/time
                byte[] timeData = BitConverter.GetBytes(DateTime.UtcNow.Ticks);
                hash.TransformBlock(timeData, 0, timeData.Length, null, 0);

                // Add process info
                byte[] processId = BitConverter.GetBytes(Environment.ProcessId);
                hash.TransformBlock(processId, 0, processId.Length, null, 0);

                // Add thread info
                byte[] threadId = BitConverter.GetBytes(Environment.CurrentManagedThreadId);
                hash.TransformBlock(threadId, 0, threadId.Length, null, 0);

                // Add memory info
                byte[] memInfo = BitConverter.GetBytes(GC.GetTotalMemory(false));
                hash.TransformBlock(memInfo, 0, memInfo.Length, null, 0);

                // Add initial entropy
                hash.TransformFinalBlock(entropy, 0, entropy.Length);

                // Get hash of all the entropy
                byte[] mixedEntropy = hash.Hash;

                // Copy the resulting entropy back to the buffer
                Array.Copy(mixedEntropy, entropy, Math.Min(mixedEntropy.Length, entropy.Length));
            }

            return entropy;
        }

        #endregion
    }
}