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
            string op = "/locations?v=1&lang=en";  // Default something if not specified.
            if(args.Length > 0)
            {
                op = args[0];
            }
            HttpResponseMessage response = SendTestRequest(op).Result;
            string json = response.Content.ReadAsStringAsync().Result;
            Console.WriteLine(json);
        }

        private static async Task<HttpResponseMessage> SendTestRequest(string op)
        {
            var organization = ConfigurationManager.AppSettings["VKSOrganization"];
            var user = ConfigurationManager.AppSettings["VKSUser"];
            var token = ConfigurationManager.AppSettings["VKSToken"];
            var baseUri = ConfigurationManager.AppSettings["VKSBaseUri"];

            var wsse = new VisualKnowledgeShare.Security.Wsse(user, organization, token);
            string wsseHeader = wsse.GenerateXwsseHeader();
            _client.DefaultRequestHeaders.Add("X-WSSE", wsseHeader);

            string uri = baseUri + op;
            //string uri = baseUri + "/guidebooks/?lang=en&v=1&name=*assembly*";  // Not sure if I'm calling this right, but returns "not implemented".

            HttpResponseMessage response = await _client.GetAsync(uri);

            return response;
        }
    }
}
