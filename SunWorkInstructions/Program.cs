using System;
using System.Text;
using System.Threading.Tasks;
using System.Net.Http;
using System.Security.Cryptography;
using System.IO;
using VisualKnowledgeShare.Security;
using System.Configuration;

namespace SunWorkInstructions
{
    class Program
    {
        private static readonly HttpClient _client = new HttpClient();

        static void Main(string[] args)
        {
            HttpResponseMessage response = SendTestRequest().Result;
            string json = response.Content.ReadAsStringAsync().Result;
        }

        private static async Task<HttpResponseMessage> SendTestRequest()
        {
            var organization = ConfigurationManager.AppSettings["VKSOrganization"];
            var user = ConfigurationManager.AppSettings["VKSUser"];
            var token = ConfigurationManager.AppSettings["VKSToken"];
            var baseUri = ConfigurationManager.AppSettings["VKSBaseUri"];

            var wsse = new VisualKnowledgeShare.Security.Wsse(user, organization, token);
            string wsseHeader = wsse.GenerateXwsseHeader();
            _client.DefaultRequestHeaders.Add("X-WSSE", wsseHeader);

            string uri = baseUri + "/locations?v=1&lang=en";
            //string uri = baseUri + "/guidebooks/?lang=en&v=1&name=*assembly*";  // Not sure if I'm calling this right, but returns "not implemented".

            HttpResponseMessage response = await _client.GetAsync(uri);

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
