using FileCryptApp.Models;
using Microsoft.VisualBasic;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace FileCryptApp.Services
{
    internal class FileSystemWatcherService
    {
        private FileSystemWatcher watcher;
        private readonly string targetPath;
        private readonly string destPath;
        private readonly Action<string> log;
        public string SelectedAlgorithm { get; set; } = "XXTEA-CBC";
        public bool IsRunning { get; private set; }

        public FileSystemWatcherService(string targetPath, string destPath, Action<string> log)
        {
            this.targetPath = targetPath;
            this.destPath = destPath;
            this.log = log;

            if (!Directory.Exists(targetPath)) Directory.CreateDirectory(targetPath);
            if (!Directory.Exists(destPath)) Directory.CreateDirectory(destPath);

            InitializeWatcher();

        }

        private void InitializeWatcher()
        {
            watcher = new FileSystemWatcher();
            watcher.Filter = "*.*";
            watcher.NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite;
            watcher.Created += OnCreated;

            watcher.EnableRaisingEvents = false;
        }

        public void Start()
        {
            try
            {

                if (!Directory.Exists(targetPath)) Directory.CreateDirectory(targetPath);


                watcher.Path = targetPath;


                watcher.EnableRaisingEvents = true;
                IsRunning = true;

                log?.Invoke($"FSW pokrenut na lokaciji: {targetPath}");
            }
            catch (Exception ex)
            {

                log?.Invoke($"Kritična greška pri pokretanju: {ex.Message}");
            }

        }

        public void Stop()
        {
            watcher.EnableRaisingEvents = false;
            IsRunning = false;
            log?.Invoke($"FSW je zaustavljen");
        }

        private void OnCreated(object sender, FileSystemEventArgs e)
        {
            try
            {
                log?.Invoke($"Detektovan fajl: {e.Name}. Ceka se pristup...");

                WaitForFile(e.FullPath);

                log?.Invoke($"Pristup odobren. Zapoceta obrada...");

                ProcessFile(e.FullPath);
            }
            catch (Exception ex)
            {
                log?.Invoke($"Greska: {ex.Message}");
            }
        }

        private void WaitForFile(string path)
        {
            int attempts = 100;

            while (attempts > 0)
            {
                try
                {
                    using (FileStream f = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.None))
                    {
                        return;
                    }
                }
                catch (IOException)
                {
                    attempts--;
                    System.Threading.Thread.Sleep(500);
                }
            }
            throw new Exception($"Fajl {path} je ostao zakljucan predugo.");

        }

        private void ProcessFile(string filePath)
        {
            try
            {
                log?.Invoke($"Započeto automatsko kodiranje: {Path.GetFileName(filePath)}");

                

                byte[] data = File.ReadAllBytes(filePath);
                
                TigerHash tiger = new TigerHash();
                byte[] hashBytes = tiger.Hash(data);
                string finalHash = Convert.ToBase64String(hashBytes);

                byte[] encryptedData;
                string chosenAlgorithm = this.SelectedAlgorithm;

                if (chosenAlgorithm == "Railfence")
                {
                    RailFenceCipher cipher = new RailFenceCipher(3);
                    encryptedData = cipher.Encrypt(data);
                }
                else
                {
                    byte[] key = KeyProvider.CurrentXXTEAKey;
                    XXTEA xxtea = new XXTEA(key);
                    CBC cbc = new CBC(xxtea);
                    encryptedData = cbc.Encrypt(data);
                }

                var metaData = new FileMetaData
                {
                    FileName = Path.GetFileName(filePath),
                    SizeBytes = data.Length,
                    Created = DateTime.Now,
                    Algorithm = chosenAlgorithm,
                    HashAlgorithm = "TigerHash",
                    HashValue = finalHash
                };

             
                string jsonHeader = metaData.ToJson();
                byte[] headerBytes = Encoding.UTF8.GetBytes(jsonHeader);
                byte[] headerLength = BitConverter.GetBytes(headerBytes.Length);

                string outPath = Path.Combine(destPath, Path.GetFileName(filePath) + ".crypt");

                using (FileStream f = new FileStream(outPath, FileMode.Create))
                {
                    f.Write(headerLength, 0, 4); 
                    f.Write(headerBytes, 0, headerBytes.Length); 
                    f.Write(encryptedData, 0, encryptedData.Length); 
                }

                log?.Invoke($"Fajl uspešno sačuvan u direktorijum X.");
            }
            catch (Exception ex)
            {
                log?.Invoke($"Greska pri obradi: {ex.Message}");
            }
        }

        public void DecryptBytes(byte[] receivedData, string outputFolder)
        {
            try
            {
                using (MemoryStream ms = new MemoryStream(receivedData))
                {

                    byte[] lengthBuffer = new byte[4];
                    ms.Read(lengthBuffer, 0, 4);
                    int headerLength = BitConverter.ToInt32(lengthBuffer, 0);


                    byte[] headerBytes = new byte[headerLength];
                    ms.Read(headerBytes, 0, headerLength);
                    string jsonHeader = Encoding.UTF8.GetString(headerBytes);
                    var meta = JsonSerializer.Deserialize<FileMetaData>(jsonHeader);

                    byte[] encryptedData = new byte[ms.Length - 4 - headerLength];
                    ms.Read(encryptedData, 0, encryptedData.Length);


                    byte[] decryptedData;
                    if (meta.Algorithm == "Railfence")
                    {
                        decryptedData = new RailFenceCipher(3).Decrypt(encryptedData);
                    }
                    else
                    {
                        byte[] key = KeyProvider.CurrentXXTEAKey;
                        decryptedData = new CBC(new XXTEA(key)).Decrypt(encryptedData);
                    }


                    TigerHash tiger = new TigerHash();
                    byte[] currentHashBytes = tiger.Hash(decryptedData);
                    string currentHashString = Convert.ToBase64String(currentHashBytes);


                    if (meta.HashValue == currentHashString)
                    {
                        log?.Invoke($"[INTEGRITET OK] Heš vrednosti se poklapaju.");
                    }
                    else
                    {
                        log?.Invoke($"[UPOZORENJE] Heš vrednosti se NE poklapaju! Fajl je možda oštećen.");
                    }

                    string finalPath = Path.Combine(outputFolder, "RECEIVED_" + meta.FileName);
                    File.WriteAllBytes(finalPath, decryptedData);
                    log?.Invoke($"Fajl sačuvan: {Path.GetFileName(finalPath)}");


                }
            }
            catch (Exception ex)
            {
                log?.Invoke($"Greška pri dekripciji: {ex.Message}");
            }
        }

        public string PreparePackageForSending(string sourceFilePath)
        {
            try
            {
                log?.Invoke($"Ručno kodiranje fajla: {Path.GetFileName(sourceFilePath)}");
                byte[] data = File.ReadAllBytes(sourceFilePath);

                TigerHash tiger = new TigerHash();
                string finalHash = Convert.ToBase64String(tiger.Hash(data));

                byte[] encryptedData;
                if (SelectedAlgorithm == "Railfence")
                {
                    encryptedData = new RailFenceCipher(3).Encrypt(data);
                }
                else
                {

                    byte[] key = KeyProvider.CurrentXXTEAKey;
                    var xxtea = new XXTEA(key);
                    var cbc = new CBC(xxtea); 

                    encryptedData = cbc.Encrypt(data);
                    log?.Invoke($"XXTEA-CBC: Enkripcija završena.");
                }

                var metaData = new FileMetaData
                {
                    FileName = Path.GetFileName(sourceFilePath),
                    SizeBytes = data.Length, 
                    Created = DateTime.Now,
                    Algorithm = SelectedAlgorithm,
                    HashAlgorithm = "TigerHash",
                    HashValue = finalHash
                };

                string tempOutPath = Path.Combine(Path.GetTempPath(), "SEND_" + Guid.NewGuid().ToString() + ".tmp");
                string jsonHeader = metaData.ToJson();
                byte[] headerBytes = Encoding.UTF8.GetBytes(jsonHeader);
                byte[] headerLength = BitConverter.GetBytes(headerBytes.Length);

                using (FileStream f = new FileStream(tempOutPath, FileMode.Create))
                {
                    f.Write(headerLength, 0, 4);
                    f.Write(headerBytes, 0, headerBytes.Length);
                    f.Write(encryptedData, 0, encryptedData.Length);
                }

                return tempOutPath;
            }
            catch (Exception ex)
            {
                log?.Invoke($"Greška pri pripremi paketa: {ex.Message}");
                return null;
            }
        }
        public void DecryptFileFromPath(string encryptedFilePath, string outputFolder)
        {
            try
            {
                if (KeyProvider.CurrentXXTEAKey == null)
                    KeyProvider.CurrentXXTEAKey = File.ReadAllBytes(@"C:\Projekat\shared.key");

                byte[] allBytes = File.ReadAllBytes(encryptedFilePath);

                if (allBytes.Length == 0)
                    throw new Exception("Primljeni fajl je prazan (0 bajtova).");

                DecryptBytes(allBytes, outputFolder);


                if (File.Exists(encryptedFilePath)) File.Delete(encryptedFilePath);
            }
            catch (Exception ex)
            {
                log?.Invoke($"Greška pri dekripciji fajla: {ex.Message}");
            }
        }
    }
}
