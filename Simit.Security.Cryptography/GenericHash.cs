namespace Simit.Security.Cryptography
{
    #region Using Directive

    using System;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;

    #endregion Using Directive

    public class GenericHash
    {
        /// <summary>
        /// Computes the hash.
        /// </summary>
        /// <typeparam name="T">MD5CryptoServiceProvider, SHA1CryptoServiceProvider,SHA512CryptoServiceProvider, etc</typeparam>
        /// <param name="data">The data.</param>
        /// <param name="convertBase64">if set to <c>true</c> [convert base64].</param>
        /// <returns>
        /// hashed string
        /// </returns>
        /// <exception cref="System.ArgumentNullException">data</exception>
        public string ComputeHash<T>(string data, bool convertBase64 = true) where T : HashAlgorithm, new()
        {
            if (data == null) throw new ArgumentNullException("data");

            HashAlgorithm provider = new T();

            provider.ComputeHash(System.Text.Encoding.UTF8.GetBytes(data));

            string result = string.Empty;
            if (convertBase64)
                result = Convert.ToBase64String(provider.Hash);
            else
            {
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < provider.Hash.Length; i++)
                {
                    sb.Append(provider.Hash[i].ToString("x2"));
                }
                result = sb.ToString().ToLower();
            }
            return result;
        }

        /// <summary>
        /// Computes the keyed hash.
        /// </summary>
        /// <typeparam name="T">HMACMD5</typeparam>
        /// <param name="data">The data.</param>
        /// <param name="convertBase64">if set to <c>true</c> [convert base64].</param>
        /// <param name="keys">The keys.</param>
        /// <returns></returns>
        /// <exception cref="System.ArgumentNullException">data
        /// or
        /// keys</exception>
        /// <exception cref="System.ArgumentException">keys must be has any items</exception>
        public string ComputeKeyedHash<T>(string data, bool convertBase64, params object[] keys) where T : KeyedHashAlgorithm, new()
        {
            if (data == null) throw new ArgumentNullException("data");
            if (keys == null) throw new ArgumentNullException("keys");
            if (keys.Length == 0) throw new ArgumentException("keys must be has any items");

            string keyData = string.Join(string.Empty, keys.Select(c => c.ToString()).ToArray());

            KeyedHashAlgorithm provider = new T { Key = System.Text.Encoding.UTF8.GetBytes(keyData) };

            provider.ComputeHash(System.Text.Encoding.UTF8.GetBytes(data));

            string result = string.Empty;
            if (convertBase64)
                result = Convert.ToBase64String(provider.Hash);
            else
            {
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < provider.Hash.Length; i++)
                {
                    sb.Append(provider.Hash[i].ToString("x2"));
                }
                result = sb.ToString().ToLower();
            }
            return result;
        }
    }
}