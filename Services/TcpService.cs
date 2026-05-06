using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace FileCryptApp.Services
{
    internal class TcpService
    {
        private readonly Action<string> log;
        private TcpListener listener;
        private bool isListening;
        public string SelectedMode { get; set; } = "KEYFILE";
        private  KeyManager keyManager;
        private RSAService rsaService = new RSAService();

        public TcpService(Action<string> log)
        {
            this.log = log;
            keyManager = new KeyManager(rsaService);
        }

        private async Task<string> ReadLineAsync(NetworkStream stream)
        {
           

            using (MemoryStream ms = new MemoryStream())
            {
                byte[] buffer = new byte[1];

                while (true)
                {
                    int read = await stream.ReadAsync(buffer, 0, 1);
                    if (read == 0)
                        break;

                    if (buffer[0] == '\n')
                        break;

                    ms.WriteByte(buffer[0]);
                }

                return Encoding.UTF8.GetString(ms.ToArray()).Trim('\r');
            }

        }

        public async Task<bool> PerformHandshakeAsync(string ip, int port)
        {
            try
            {
                log?.Invoke("TCP: Povezivanje radi RSA handshakе-a...");
                TcpClient client = new TcpClient();
                await client.ConnectAsync(ip, port);

                NetworkStream stream = client.GetStream();
                
                    if (SelectedMode == "KEYFILE")
                    {
                        
                        return true;
                    }

                    await stream.WriteAsync(Encoding.UTF8.GetBytes("HELLO_RSA?\n"));



                    string response = "";
                    try
                    {
                        response = await ReadLineAsync(stream);
                    }
                    catch { }

                    if (response != "RSA_OK")
                    {
                        log?.Invoke("Server NE podržava RSA → prelazak na KEYFILE.");
                        KeyProvider.CurrentXXTEAKey = keyManager.LoadKey(@"C:\Projekat\shared.key");
                        return true;
                    }

                 
                    string jsonPub = await ReadLineAsync(stream);
                    RSAParameters serverPublic = JsonSerializer.Deserialize<RSAParameters>(jsonPub);
                    log("CLIENT RAW JSON = [" + jsonPub + "]");
                    log("CLIENT JSON LENGTH = " + jsonPub.Length);
                    byte[] xxteaKey = keyManager.GenerateXXTEAKey();
                   

                    byte[] encryptedKey = keyManager.EncryptKeyRSA(xxteaKey, serverPublic);

                    log("Encrypted key bytes: " + encryptedKey.Length);

                    await stream.WriteAsync(encryptedKey);
                    await stream.FlushAsync();

                    string done = await ReadLineAsync(stream);
                    if (done != "RSA_DONE")
                    {
                        log("Server not ready for file");
                        return false;
                    }

                    KeyProvider.CurrentXXTEAKey = xxteaKey;

                    log?.Invoke("RSA handshake uspešan. XXTEA ključ razmenjen.");
                    stream.Close();
                    stream.Dispose();
                    client.Close();
                    client.Dispose();

                    return true;
                
            }
            catch (Exception ex)
            {
                log?.Invoke($"RSA Handshake greška: {ex.Message}");
                return false;
            }
        }
        public async Task SendFileAsync(string filePath, string ipAddress, int port)
        {
            TcpClient tcpClient = null;
            try
            {
                log?.Invoke($"TCP: Povezivanje na {ipAddress}:{port}...");
                tcpClient = new TcpClient();
                await tcpClient.ConnectAsync(ipAddress, port);

                using (NetworkStream stream = tcpClient.GetStream())
                using (FileStream f = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                {
                    log?.Invoke($"TCP: Šaljem paket ({f.Length} bytes)...");

                    await f.CopyToAsync(stream);
                    await stream.FlushAsync();
                    log?.Invoke("TCP: Slanje uspešno!");
                }
            }
            catch (Exception ex)
            {
                log?.Invoke($"TCP GREŠKA: {ex.Message}");
            }
            finally
            {
                tcpClient?.Close();
                tcpClient?.Dispose();
            }
        }
        public async Task StartListeningAsync(int port, Action<string> onFileReceivedPath)
        {
            if (isListening) return;

            listener = new TcpListener(IPAddress.Any, port);
            listener.Start();
            isListening = true;
            log?.Invoke($"TCP Server pokrenut na portu {port}. Čekam...");

            while (isListening)
            {
                TcpClient client = await listener.AcceptTcpClientAsync();

                _ = Task.Run(async () =>
                {
                    string tempFileName = $"incoming_{DateTime.Now.Ticks}.crypt";
                    string savePath = Path.Combine(@"C:\Projekat\Primljeno", tempFileName);

                    try
                    {
                        using (client)
                        using (NetworkStream stream = client.GetStream())
                        {
                            int first = stream.ReadByte();
                            if (first == -1) return;

                            
                            if (first == (byte)'H')
                            {
                                string rest = await ReadLineAsync(stream);
                                string command = "H" + rest;
                                log($"SERVER CMD = [{command}]");

                                if (command == "HELLO_RSA?")
                                {
                                    
                                    await stream.WriteAsync(Encoding.UTF8.GetBytes("RSA_OK\n"));

                               
                                    RSAParameters pub = rsaService.GetPublicKey();
                                    string jsonPub = JsonSerializer.Serialize(pub) + "\n";
                                    await stream.WriteAsync(Encoding.UTF8.GetBytes(jsonPub));

                                    byte[] encKey = new byte[256];
                                    await ReadExact(stream, encKey);

                                    byte[] xxteaKey = keyManager.DecryptKeyRSA(encKey, rsaService.GetPrivateKey());
                                    KeyProvider.CurrentXXTEAKey = xxteaKey;

                                   
                                    await stream.WriteAsync(Encoding.UTF8.GetBytes("RSA_DONE\n"));
                                    await stream.FlushAsync();

                                    log("SERVER: RSA handshake završen.");
                                    return; 
                                }
                            }

                            using (FileStream fs = new FileStream(savePath, FileMode.Create))
                            {
                                fs.WriteByte((byte)first);
                                await stream.CopyToAsync(fs);
                            }

                            onFileReceivedPath(savePath);
                        }
                    }
                    catch (Exception ex)
                    {
                        log?.Invoke($"Greška pri prijemu bajtova: {ex.Message}");
                    }
                });
            }
        }

        public void StopListening()
        {
            isListening = false;
            listener?.Stop();
            log?.Invoke($"TCP Server zaustavljen.");
        }
        private async Task ReadExact(NetworkStream s, byte[] buffer)
        {
            int offset = 0;
            while (offset < buffer.Length)
            {
                int read = await s.ReadAsync(buffer, offset, buffer.Length - offset);
                if (read == 0) throw new Exception("Connection closed during key read.");
                offset += read;
            }
        }
    }

}
