/**
 * @author Nathan Appleby
 */

using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Numerics;
using System.Security.Cryptography;

namespace Messenger
{
    public class Messenger
    {
        static readonly HttpClient client = new HttpClient();

        public static async Task Main(string[] args)
        {
            if (args.Length > 0)
            {
                if (args[0].Equals("getKey"))
                {
                    if (args.Length > 1)
                    {
                        await GetKey(args[1]);
                    }
                    else
                    {
                        Console.WriteLine("Usage: getKey [email]");
                    }
                }
                else if (args[0].Equals("keyGen"))
                {
                    if (args.Length > 1)
                    {
                        try
                        {
                            if (Int32.Parse(args[1]) % 8 == 0)
                            {
                                KeyGen(Int32.Parse(args[1]));
                            }
                            else
                            {
                                Console.WriteLine("Number of bits must be divisible by 8");
                            }
                        }
                        catch (ArgumentNullException)
                        {
                            Console.WriteLine("Must have a number of bits");
                        }
                        catch (FormatException)
                        {
                            Console.WriteLine("Needs to be a number");
                        }
                        catch (OverflowException)
                        {
                            Console.WriteLine("Number too big!");
                        }
                    }
                    else
                    {
                        Console.WriteLine("Usage: keyGen [bitcount]");
                    }
                }
                else if (args[0].Equals("sendKey"))
                {
                    if (args.Length > 1)
                    {
                        if (File.Exists("public.key") && File.Exists("private.key"))
                        {
                            await SendKey(args[1]);
                        }
                        else
                        {
                            Console.WriteLine("Error: Generate a key before attempting to send a key.");
                        }
                    }
                    else
                    {
                        Console.WriteLine("Usage: sendKey [email]");
                    }
                }
                else if (args[0].Equals("getMsg"))
                {
                    if (args.Length > 1)
                    {
                        var privateKey = File.ReadAllText("private.key");
                        PrivateKey pk = JsonSerializer.Deserialize<PrivateKey>(privateKey)!;
                        if (pk.Emails.Contains(args[1]))
                        {
                            await GetMsg(args[1], pk);
                        }
                        else
                        {
                            Console.WriteLine("These messages cannot be decoded.");
                        }
                    }
                    else
                    {
                        Console.WriteLine("Usage: getMsg [email]");
                    }
                }
                else if (args[0].Equals("sendMsg"))
                {
                    if (args.Length > 2)
                    {
                        if (File.Exists(args[1] + ".key"))
                        {
                            await SendMsg(args[1], args[2]);
                        }
                        else
                        {
                            Console.WriteLine("Key does not exist for " + args[1] + ".rit.edu");
                        }
                    }
                    else
                    {
                        Console.WriteLine("Usage: sendMsg [email] [message]");
                    }
                }
                else
                {
                    Console.WriteLine("Usage:\tgetKey [email]\n\tkeyGen [bitsize]\n\tsendKey [email]" +
                                      "\n\tgetMsg [email]\n\tsendMsg [email] [message]");
                }
            }
            else
            {
                Console.WriteLine("Usage:\tgetKey [email]\n\tkeyGen [bitsize]\n\tsendKey [email]" +
                                  "\n\tgetMsg [email]\n\tsendMsg [email] [message]");
            }
        }

        /**
         * Gets the key from the server
         */
        static async Task GetKey(string email)
        {
            try
            {
                string request = "http://kayrun.cs.rit.edu:5000/Key/" + email;

                using HttpResponseMessage response = await client.GetAsync(request);
                response.EnsureSuccessStatusCode();
                string responseBody = await response.Content.ReadAsStringAsync();

                string keyFile = email + ".key";
                File.WriteAllText(keyFile, responseBody);
                
                Console.WriteLine("Key saved\n");
            }
            catch (HttpRequestException e)
            {
                Console.WriteLine("\nException Caught!");
                Console.WriteLine("Message :{0} ", e.Message);
            }
        }

        /**
         * Deserializes the key
         */
        static PublicKey DeserializeKey(string email)
        {
            string jsonKey = File.ReadAllText(email + ".key");
            PublicKey key = JsonSerializer.Deserialize<PublicKey>(jsonKey)!;
            return key;
        }

        /**
         * Takes in a key and outputs the E/D and N from the Base64 key
         */
        static (BigInteger, BigInteger) ParseKey(string key)
        {
            byte[] bytes = Convert.FromBase64String(key);

            byte[] eArr = new byte[4];
            Array.Copy(bytes, 0, eArr, 0, 4);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(eArr);
            }

            int e = BitConverter.ToInt32(eArr, 0);

            byte[] EArr = new byte[e];
            Array.Copy(bytes, 4, EArr, 0, e);

            BigInteger E = new BigInteger(EArr);

            byte[] nArr = new byte[4];
            Array.Copy(bytes, 4 + e, nArr, 0, 4);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(nArr);
            }

            int n = BitConverter.ToInt32(nArr, 0);

            byte[] NArr = new byte[n];
            Array.Copy(bytes, 8 + e, NArr, 0, n);
            BigInteger N = new BigInteger(NArr);
            return (E, N);
        }

        /**
         * Provided modInverse function
         */
        static BigInteger modInverse(BigInteger a, BigInteger n)
        {
            BigInteger i = n, v = 0, d = 1;
            while (a > 0)
            {
                BigInteger t = i / a, x = a;
                a = i % x;
                i = x;
                x = d;
                d = v - t * x;
                v = x;
            }

            v %= n;
            if (v < 0) v = (v + n) % n;
            return v;
        }

        /**
         * Generates a key based on a bit count, using the E of 7949
         */
        static public void KeyGen(int bitcount)
        {

            int pLength = bitcount * 2 / 5;
            pLength -= pLength % 8;
            int qLength = bitcount - pLength;
            Console.WriteLine((pLength, qLength));
            PrimeGen pr = new PrimeGen();
            BigInteger p = pr.PrimeGenerator(pLength);
            BigInteger q = pr.PrimeGenerator(qLength);
            Console.WriteLine((p, q));

            BigInteger N = p * q;
            Console.WriteLine(N);
            BigInteger r = (p - 1) * (q - 1);
            BigInteger E = 7949;
            BigInteger D = modInverse(E, r);

            int byteCountN = N.GetByteCount();
            byte[] n = BitConverter.GetBytes(byteCountN);
            int byteCountE = E.GetByteCount();
            byte[] e = BitConverter.GetBytes(byteCountE);
            int byteCountD = D.GetByteCount();
            byte[] d = BitConverter.GetBytes(byteCountD);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(n);
                Array.Reverse(e);
                Array.Reverse(d);
            }

            byte[] bytesN = N.ToByteArray();
            byte[] bytesE = E.ToByteArray();
            byte[] bytesD = D.ToByteArray();

            byte[] publickey = new byte[4 + byteCountE + 4 + byteCountN];
            byte[] privatekey = new byte[4 + byteCountD + 4 + byteCountN];
            Array.Copy(e, 0, publickey, 0, 4);
            Array.Copy(bytesE, 0, publickey, 4, byteCountE);
            Array.Copy(n, 0, publickey, 4 + byteCountE, 4);
            Array.Copy(bytesN, 0, publickey, 8 + byteCountE, byteCountN);

            Array.Copy(d, 0, privatekey, 0, 4);
            Array.Copy(bytesD, 0, privatekey, 4, byteCountD);
            Array.Copy(n, 0, privatekey, 4 + byteCountD, 4);
            Array.Copy(bytesN, 0, privatekey, 8 + byteCountD, byteCountN);

            string publicEncoded = Convert.ToBase64String(publickey);
            string privateEncoded = Convert.ToBase64String(privatekey);
            PublicKey publicKey = new PublicKey(publicEncoded);
            PrivateKey privateKey = new PrivateKey(new List<string>(), privateEncoded);

            string publicSerialized = JsonSerializer.Serialize(publicKey);
            string privateSerialized = JsonSerializer.Serialize(privateKey);

            File.WriteAllText("public.key", publicSerialized);
            File.WriteAllText("private.key", privateSerialized);
        }

        static async Task SendKey(string email)
        {
            PublicKey key = DeserializeKey("public");
            PublicKey sendKey = new PublicKey(email, key.Key);
            try
            {
                string request = "http://kayrun.cs.rit.edu:5000/Key/" + email;
                using HttpResponseMessage response = await client.PutAsJsonAsync(request, sendKey);
                response.EnsureSuccessStatusCode();

                string privKey = File.ReadAllText("private.key");
                PrivateKey privateKey = JsonSerializer.Deserialize<PrivateKey>(privKey)!;
                privateKey.AddEmail(email);
                string addedEmail = JsonSerializer.Serialize(privateKey);
                File.WriteAllText("private.key", addedEmail);
                
                Console.WriteLine("Key saved");
            }
            catch (HttpRequestException e)
            {
                Console.WriteLine("\nException Caught!");
                Console.WriteLine("Message :{0} ", e.Message);
            }
        }

        /**
         * Gets a message from the server and decodes it
         */
        static async Task GetMsg(string email, PrivateKey pk)
        {
            try
            {
                string request = "http://kayrun.cs.rit.edu:5000/Message/" + email;

                using HttpResponseMessage response = await client.GetAsync(request);
                response.EnsureSuccessStatusCode();
                string responseBody = await response.Content.ReadAsStringAsync();
                Message message = JsonSerializer.Deserialize<Message>(responseBody)!;

                byte[] messageBytes = Convert.FromBase64String(message.content);
                BigInteger messageInteger = new BigInteger(messageBytes);
                (BigInteger d, BigInteger n) = ParseKey(pk.Key);
                
                BigInteger postDecrypt = BigInteger.ModPow(messageInteger, d, n);

                byte[] decryptedArray = postDecrypt.ToByteArray();

                string decodedMessage = Encoding.Default.GetString(decryptedArray);
                
                Console.WriteLine(decodedMessage);
            }
            catch (HttpRequestException e)
            {
                Console.WriteLine("\nException Caught!");
                Console.WriteLine("Message :{0} ", e.Message);
            }
        }

        /**
         * Encodes a message for someone else, encodes it with their public key, and sends it to the server
         */
        static async Task SendMsg(string email, string content)
        {
            PublicKey key = DeserializeKey(email);
            (BigInteger E, BigInteger N) = ParseKey(key.Key);
            byte[] preEncryptionArray = Encoding.Default.GetBytes(content);
            BigInteger preEncryption = new BigInteger(preEncryptionArray);

            BigInteger postEncryption = BigInteger.ModPow(preEncryption, E, N);

            byte[] postEncryptionArray = postEncryption.ToByteArray();
            
            string postEncryptionContent = Convert.ToBase64String(postEncryptionArray);

            Message message = new Message(email, postEncryptionContent);
            
            try
            {
                string request = "http://kayrun.cs.rit.edu:5000/Message/" + email;
                using HttpResponseMessage response = await client.PutAsJsonAsync(request, message);
                response.EnsureSuccessStatusCode();
                Console.WriteLine("\nMessage written\n");
            }
            catch (HttpRequestException e)
            {
                Console.WriteLine("\nException Caught!");
                Console.WriteLine("Message :{0} ", e.Message);
            }
        }
    }

    /**
     * Object to store public keys
     */
    public class PublicKey
    {
        public PublicKey(string key)
        {
            Key = key;
        }

        public PublicKey(string email, string key)
        {
            Email = email;
            Key = key;
        }

        public PublicKey()
        {
            Key = "";
        }

        [JsonPropertyName("email")] public string? Email { get; set; }
        [JsonPropertyName("key")] public string Key { get; set; }

        public new string ToString()
        {
            return "Email: " + this.Email + "\nPublic Key: " + this.Key;
        }
    }

    /**
     * class to store private keys
     */
    public class PrivateKey
    {
        [JsonPropertyName("emails")] 
        public List<string> Emails { get; set; }

        [JsonPropertyName("key")]
        public string Key { get; set; }

        public PrivateKey(List<string> emails, string key)
        {
            Emails = emails;
            Key = key;
        }

        public void AddEmail(string email)
        {
            Emails.Add(email);
        }
    }

    /**
     * Class to shuttle messages into the server
     */
    public class Message
    {
        public string email { get; set; }
        public string content { get; set; }

        public Message(string email, string content)
        {
            this.email = email;
            this.content = content;
        }
    }

    /**
     * PREVIOUS PROJECT, MODIFIED SLIGHTLY TO WORK FOR THIS PROJECT'S NEEDS
     */
    class PrimeGen
    {
        /**
     * The main method
     */
        public PrimeGen()
        {
            
        }
        
        public BigInteger PrimeGenerator(int bitcount)
        {
            var bits = bitcount;

            if (bits < 32 || bits % 8 != 0)
            {
                throw new Exception();
            }

            var byteCount = bits / 8;
            int[] counting = { 1 };
            
            var thousand = PrimeList();

            
            BigInteger bi;
            byte[] random = new Byte[byteCount];
            var rng = RandomNumberGenerator.Create();
            rng.GetBytes(random);
            bi = new BigInteger(random);
            if (bi.Sign == -1)
            {
                bi = BigInteger.Negate(bi);
            }

            while (!IsProbablyPrime(bi, byteCount, thousand))
            {
                    rng.GetBytes(random);
                    bi = new BigInteger(random);
                    if (bi.Sign == -1)
                    {
                        bi = BigInteger.Negate(bi);
                    }
            }

            return bi;
        }


        /**
     * An implementation of the Miller-Rabin method of determining if a number is prime
     * @params:
     *      value: BigInteger           - the number to be checked for primality
     *      byteCount: int              - the number of bytes of the value
     *      firstThousand: BigInteger[] - the first thousand primes
     *      k: int                      - (optional) the amount of passes to do for the primality check
     * @returns:
     *      Whether or not the value is (probably) prime
     */
        private Boolean IsProbablyPrime(BigInteger value, int byteCount, BigInteger[] firstThousand, int k = 10)
        {
            foreach (var thing in firstThousand)
            {
                if (BigInteger.Compare(BigInteger.Remainder(value, thing), BigInteger.Zero) == 0)
                {
                    return false;
                }
            }

            if (value.IsEven)
            {
                return false;
            }

            var d = BigInteger.Subtract(value, new BigInteger(1));
            var r = 0;
            while (d.IsEven)
            {
                d = BigInteger.Divide(d, new BigInteger(2));
                r++;
            }

            BigInteger a;
            for (int i = 0; i < k; i++)
            {
                WitnessLoop:
                a = RandomBigInt(value, byteCount);
                var x = BigInteger.ModPow(a, d, value);
                if (BigInteger.Compare(x, BigInteger.One) == 0 ||
                    BigInteger.Compare(x, BigInteger.Subtract(value, BigInteger.One)) == 0)
                {
                    continue;
                }

                for (int j = 0; j < r - 1; j++)
                {
                    x = BigInteger.ModPow(x, new BigInteger(2), value);
                    if (BigInteger.Compare(x, BigInteger.Subtract(value, BigInteger.One)) == 0)
                    {
                        goto WitnessLoop;
                    }
                }

                return false;
            }

            return true;
        }

        /**
     * Generates a random BigInteger given an upperbound and byte count for use in IsProbablyPrime
     * @params:
     *      upperBound: BigInteger  - the upper limit of the random number
     *      byteCount: int          - the number of bytes for the number to generate
     * @returns:
     *      bi: BigInteger  - a random number
     */
        private BigInteger RandomBigInt(BigInteger upperBound, int byteCount)
        {
            byte[] random = new Byte[byteCount];
            var rng = RandomNumberGenerator.Create();
            rng.GetBytes(random);
            var bi = new BigInteger(random);
            if (bi.Sign == -1)
            {
                bi = BigInteger.Negate(bi);
            }

            bi = BigInteger.Remainder(bi, BigInteger.Subtract(upperBound, BigInteger.One));

            return bi;
        }

        /**
     * generates a list of the first 1000 prime numbers in order to speed up checking primality
     * @returns:
     *      arr: BigInteger[]   - a list of the first 1000 primes
     */
        private BigInteger[] PrimeList()
        {
            BigInteger[] arr = new BigInteger[1000];
            int index = 1;
            int i = 3;
            arr[0] = new BigInteger(2);
            while (BigInteger.Compare(arr[999], BigInteger.Zero) == 0)
            {
                int k = 0;
                for (int j = 2; j < i; j++)
                {
                    if (i % j == 0)
                    {
                        k = 1;
                    }
                }

                if (k == 0)
                {
                    arr[index++] = new BigInteger(i++);
                }
                else
                {
                    i++;
                }
            }

            return arr;
        }

    }
}

