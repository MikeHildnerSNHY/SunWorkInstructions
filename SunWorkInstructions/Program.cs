using System;
using System.Text;
using System.Threading.Tasks;
using System.Net.Http;
using System.Security.Cryptography;
using System.IO;
using VisualKnowledgeShare.Security;

namespace SunWorkInstructions
{
    class Program
    {
        private static readonly HttpClient _client = new HttpClient();

        static void Main(string[] args)
        {
            SendRequest2().Wait();
        }

        private static async Task<HttpResponseMessage> SendRequest2()
        {
            //var user = "api.connector";
            var user = "mhildner";
            var organization = "Sun Hydraulics";
            //var apiToken = "bXRzNzh0UHlBSVZ1RkVoU29CQkdvdUxaYmsyaTlRQWE2MlgxSkFvaG9za0xxendSMTBWeHR0ekRrNVlvcElONGdBZCtJdnFiQlVLTmx4UzhtdGNuWXpBcmsyL2RSOXRMR1E1K1BmTGhkQVA2ZGwyZW56MDJmMzVJK3lGLzUvZjk=";
            var mikesToken = "OU54T1kvc3NkWktTaFRCSzBTSHFKWFFRY1h6dmFldjNDMjZjeUNRQVk3V0F5WktSdWRMek1NOXVIL1FaMXNrMEZ1TmJiUm5YNUlJK29WQVFNeTlqUUREOWdCVDBQT0lYTlZ3Y0I5SkpNL0lJZXBvUG9VU3h5QVZXSWhEVEpMTHY=";
            var wsse = new VisualKnowledgeShare.Security.Wsse(user, organization, mikesToken);
            string wsseHeader = wsse.GenerateXwsseHeader();
            _client.DefaultRequestHeaders.Add("X-WSSE", wsseHeader);

            //HttpResponseMessage response = await _client.GetAsync("https://vwi.sunhydraulics.com/dqs/guidebooks/?lang=en&v=1&name=*assembly*");
            HttpResponseMessage response = await _client.GetAsync("https://vwi.sunhydraulics.com/dqs/locations?v=1&lang=en");

            return response;
        }

        private static async Task<HttpResponseMessage> SendRequest()
        {
            string wsseHeader = CreateWsseHeader();

            _client.BaseAddress = new Uri("https://vwi.sunhydraulics.com/dqs/");
            _client.DefaultRequestHeaders.Add("Accept", "application/json");
            //_client.DefaultRequestHeaders.Add("Authorization", "WSSE profile=\"UsernameToken\"");
            _client.DefaultRequestHeaders.Add("X-WSSE", wsseHeader);

            HttpResponseMessage response = await _client.GetAsync("https://vwi.sunhydraulics.com/dqs/guidebooks/?lang=en&v=1&name=*assembly*");
            return response;
        }

        private static string CreateWsseHeader()
        {
            //string username = @"sun\mhildner";
            string username = "VKS.User";
            string organization = "Sun Hydraulics";
            //string mikestoken = "QkU4ZW84TVNRb25lZnByUit5YmtyU1l6Yjc1YlIrcmIwaklGWDREZjdVQUtGVm9LekpWTjV1YWF1NDUrWkNKcWMzSEh5SS93Qzd0R1I2MlVCUmV5ZzhKc3BXV3IyQ0Qvbi9JWXZIVE9qL3lid1lqWDBmNmNzek5KRCs0dzZIdmI=";
            string token = "dVV6ZE5rRjFUTFc5cXU1bEE2VFoyYTZZMFFsS2dTVHdMSzRva2YrUVpCNXdxeVZLMHVJU2QyeHNLUlQ2VHNmUzl4WUpRNm9rM2JNcXpsckEyd25HWUltWFc2NUVRb1ovejBKVmt0dS9VRSs5dW52R2hqM2plS1hoM2Iza3d3SHo=";
            byte[] nonce;

            string secret = "";

            DateTimeOffset thisDate2 = DateTime.UtcNow;

            string dateCreated = String.Format("{0:yyyy-MM-ddTH:mm:sszzz}", thisDate2);



            byte[] key;

            using (var md5 = MD5.Create())
            {
                key = md5.ComputeHash(Encoding.UTF8.GetBytes(username));
            }

            key = BytesToLowerHexBytes(key);

            var iv = Convert.FromBase64String(token);

            if (iv.Length != 16)
            {
                Array.Resize(ref iv, 16);
            }

            byte[] encrypted;
            int encryptedLength;

            using (var rijndael = new RijndaelManaged())
            {
                rijndael.Mode = CipherMode.CFB;
                //rijndael.Mode = CipherMode.CBC;
                rijndael.Padding = PaddingMode.Zeros;
                rijndael.KeySize = 256;



                using (var msEncrypt = new MemoryStream())
                {
                    var buffer = Encoding.UTF8.GetBytes(token);

                    using (ICryptoTransform encryptor = rijndael.CreateEncryptor(key, iv))
                    using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        csEncrypt.Write(buffer, 0, buffer.Length);
                    }

                    // CFB is a stream cipher, where the length of the encrypted text should be
                    // equal to the length of the original text... So we strip the last bytes
                    encrypted = msEncrypt.GetBuffer();
                    encryptedLength = buffer.Length;
                }
            }





            //   var buffer2 = Encoding.UTF8.GetBytes(Convert.ToBase64String(encrypted, 0, encryptedLength));
            var buffer2 = Encoding.UTF8.GetBytes(Convert.ToBase64String(encrypted, 0, encryptedLength));

            using (var ms = new MemoryStream(iv.Length + buffer2.Length))
            {
                ms.Write(iv, 0, iv.Length);


                ms.Write(buffer2, 0, buffer2.Length);

                secret = Convert.ToBase64String(ms.GetBuffer(), 0, (int)ms.Length);


            }

            using (var md5 = MD5.Create())
            {
                nonce = md5.ComputeHash(Guid.NewGuid().ToByteArray());
            }


            string base64Nonce = Convert.ToBase64String(nonce);
            var hash2 = HashItThePHPWay(nonce + dateCreated + secret);

            string passwordDigest = Convert.ToBase64String(Encoding.UTF8.GetBytes(hash2));

            string wsseHeader = string.Format("UsernameToken Username=\"" + username + "\",PasswordDigest=\"" + passwordDigest +
             "\", Nonce=\"" + base64Nonce + "\", Created=\"" + dateCreated + "\"" +
             ", Organization=\"" + organization + "\"");

            return wsseHeader;
        }
        private static byte[] BytesToLowerHexBytes(byte[] bytes)
        {
            // The hash is a hex string
            var bytes2 = new byte[bytes.Length * 2];

            for (int i = 0, j = 0; i < bytes.Length; i++)
            {
                byte b1 = (byte)(bytes[i] >> 4);
                bytes2[j] = (byte)(b1 <= 9 ? '0' + b1 : 'a' + b1 - 10);
                j++;
                byte b2 = (byte)(bytes[i] & 15);
                bytes2[j] = (byte)(b2 <= 9 ? '0' + b2 : 'a' + b2 - 10);
                j++;
            }

            return bytes2;
        }

        private static string HashItThePHPWay(string hashMe)
        {
            var sha = new SHA1CryptoServiceProvider();
            string b64 = ByteArrayToString(Encoding.ASCII.GetBytes(hashMe));
            var b64Bytes = Encoding.ASCII.GetBytes(b64);
            var result = sha.ComputeHash(b64Bytes);
            return BitConverter.ToString(result).Replace("-", "").ToLower();
        }

        private static string ByteArrayToString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
            {
                hex.AppendFormat("{0:x2}", b);
            }
            return hex.ToString().ToLower();
        }


    }
}
//class Program
//{
//    private static readonly HttpClient _client = new HttpClient();
//    static void Main(string[] args)
//    {
//        GetAsync().Wait();

//    }

//    static async Task<HttpResponseMessage> GetAsync()
//    {
//        _client.BaseAddress = new Uri("https://vwi.sunhydraulics.com/dqs/");
//        _client.DefaultRequestHeaders.Add("Accept", "application/json");
//        _client.DefaultRequestHeaders.Add("Authorization", "WSSE profile=\"UsernameToken\"");

//        string organization = "Sun Hydraulics";
//        string userName = "Mike Hildner";
//        byte[] key = CreateMD5(userName);
//        string token = "QkU4ZW84TVNRb25lZnByUit5YmtyU1l6Yjc1YlIrcmIwaklGWDREZjdVQUtGVm9LekpWTjV1YWF1NDUrWkNKcWMzSEh5SS93Qzd0R1I2MlVCUmV5ZzhKc3BXV3IyQ0Qvbi9JWXZIVE9qL3lid1lqWDBmNmNzek5KRCs0dzZIdmI=";
//        byte[] tokenBytes = Convert.FromBase64String(token);
//        byte[] iv = new byte[16];
//        Buffer.BlockCopy(tokenBytes, 0, iv, 0, 16);


//        // OpenSsl stuff.
//        string cryptAlgo = "AES-256-CFB";
//        //byte[] data = Convert.FromBase64String(token);
//        //string dataString = Encoding.UTF8.GetString(data);
//        Aes aes = AesManaged.Create();
//        ICryptoTransform encryptor = aes.CreateEncryptor(key, iv);
//        byte[] outputBuffer = new byte[tokenBytes.Length];
//        var x = encryptor.TransformBlock(tokenBytes, 0, tokenBytes.Length, outputBuffer, 0);
//        string secret = Convert.ToBase64String(outputBuffer);

//        string nonce = GenerateUniqueKey(64);
//        string currentTime = DateTime.Now.ToUniversalTime().ToString("yyyy'-'MM'-'dd'T'HH':'mm':'ss'+00:00'");

//        string stringToSha = nonce + currentTime + secret;
//        byte[] bytesToSha = Encoding.ASCII.GetBytes(stringToSha);
//        byte[] sha = SHA1.Create().ComputeHash(bytesToSha);
//        var reversedSha = sha.Reverse().ToArray();
//        string passwordDigest = Convert.ToBase64String(reversedSha);
//        string xWsseHeader = string.Format("UsernameToken Username=\"{0}\",PasswordDigest=\"{1}\",Nonce=\"{2}\",Created=\"{3}\",Organization=\"{4}\"", userName, passwordDigest, nonce, currentTime, organization);
//        _client.DefaultRequestHeaders.Add("X-WSSE", xWsseHeader);

//        var values = new Dictionary<string, string>
//        {

//        };

//        HttpResponseMessage response = await _client.GetAsync("https://vwi.sunhydraulics.com/dqs/guidebooks/?lang=en&v=1&name=*assembly*");

//        return response;

//    }

//    static byte[] CreateMD5(string input)
//    {
//        // Use input string to calculate MD5 hash
//        using (MD5 md5 = MD5.Create())
//        {
//            byte[] inputBytes = Encoding.ASCII.GetBytes(input);
//            byte[] hashBytes = md5.ComputeHash(inputBytes);

//            return hashBytes;
//        }
//    }

//    static string GenerateUniqueKey(int maxSize)
//    {
//        char[] chars = new char[62];
//        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890".ToCharArray();
//        byte[] data = new byte[1];
//        using (RNGCryptoServiceProvider crypto = new RNGCryptoServiceProvider())
//        {
//            crypto.GetNonZeroBytes(data);
//            data = new byte[maxSize];
//            crypto.GetNonZeroBytes(data);
//        }
//        StringBuilder result = new StringBuilder(maxSize);
//        foreach (byte b in data)
//        {
//            result.Append(chars[b % (chars.Length)]);
//        }
//        return result.ToString();
//    }
//}
//}
