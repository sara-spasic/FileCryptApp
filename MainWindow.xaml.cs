using FileCryptApp.Services;
using Microsoft.VisualBasic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using Path = System.IO.Path;

namespace FileCryptApp
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private FileSystemWatcherService fswService;
        private TcpService tcpService;
        private KeyManager keyManager;

        public MainWindow()
        {
            InitializeComponent();

            string pathTarget = @"C:\Projekat\Target";
            string pathX = @"C:\Projekat\X";
            Directory.CreateDirectory(@"C:\Projekat\Primljeno");

            fswService = new FileSystemWatcherService(pathTarget, pathX, (msg) =>
            {
                Dispatcher.Invoke(() => AddLog(msg));
            });

            tcpService = new TcpService(message => Dispatcher.Invoke(() => AddLog(message)));
            keyManager = new KeyManager(new RSAService());
        }

        private void AddLog(string message)
        {
            string logEntry = $"[{DateTime.Now:HH:mm:ss}] {message}";
            if (lstLogs != null) lstLogs.Items.Insert(0, logEntry);
        }

        private void btnStartFSW_Click(object sender, RoutedEventArgs e)
        {
            fswService.Start();
            btnStartFSW.IsEnabled = false;
            btnStopFSW.IsEnabled = true;
            txtStatus.Text = "FSW AKTIVAN - Prati folder Target";

        }

        private void btnStopFSW_Click(object sender, RoutedEventArgs e)
        {
            fswService.Stop();
            btnStartFSW.IsEnabled = true;
            btnStopFSW.IsEnabled = false;
            txtStatus.Text = "Spremno.";
        }

        private void cmbAlgorithm_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (fswService != null && cmbAlgorithm.SelectedItem is ComboBoxItem item)
            {
                fswService.SelectedAlgorithm = item.Content.ToString();
                AddLog($"Promenjen algoritam na: {item.Content}");
            }
        }

        

        private async void BtnStartServer_Click(object sender, RoutedEventArgs e)
        {
            if (!int.TryParse(txtPort.Text, out int port)) port = 8080;

           
            _ = tcpService.StartListeningAsync(port, (filePath) => {
                Dispatcher.Invoke(() => {
                    AddLog($"TCP: Fajl primljen i sačuvan na: {System.IO.Path.GetFileName(filePath)}");

                    
                    string folderZaPrimljene = @"C:\Projekat\Primljeno";

                    
                    fswService.DecryptFileFromPath(filePath, folderZaPrimljene);
                });
            });

            btnConnect.IsEnabled = false; 
            txtStatus.Text = $"SERVER AKTIVAN na portu {port}";
        }


        private async void BtnSend_Click(object sender, RoutedEventArgs e)
        {
            var openFileDialog = new Microsoft.Win32.OpenFileDialog();
            openFileDialog.Title = "Izaberi originalni fajl za kriptovanje i slanje";
            openFileDialog.Filter = "All files (*.*)|*.*";

            if (openFileDialog.ShowDialog() == true)
            {
                string sourceFilePath = openFileDialog.FileName;

                string ip = txtIpAddress.Text;
                if (!int.TryParse(txtPort.Text, out int port)) port = 8080;

                btnSendFile.IsEnabled = false;

                try
                {
                    if (tcpService.SelectedMode == "KEYFILE")
                    {
                        string encryptedPackagePath = fswService.PreparePackageForSending(sourceFilePath);

                        await tcpService.SendFileAsync(encryptedPackagePath, ip, port);

                        if (File.Exists(encryptedPackagePath))
                            File.Delete(encryptedPackagePath);

                        AddLog("TCP: Slanje uspešno završeno (KEYFILE mode).");
                        return;
                    }

                    await tcpService.PerformHandshakeAsync(ip, port);

                    string encryptedPackageRSA = fswService.PreparePackageForSending(sourceFilePath);

                    await tcpService.SendFileAsync(encryptedPackageRSA, ip, port);

                    if (File.Exists(encryptedPackageRSA))
                        File.Delete(encryptedPackageRSA);

                    AddLog("TCP: Slanje uspešno završeno (RSA mode).");
                }
                catch (Exception ex)
                {
                    AddLog($"DETALJI GREŠKE: {ex.Message}");
                }
                finally
                {
                    btnSendFile.IsEnabled = true;
                }
            }
        }

        private void BtnGenKey_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                byte[] key = keyManager.GenerateXXTEAKey();

                string path = @"C:\Projekat\shared.key";
                Directory.CreateDirectory(Path.GetDirectoryName(path));
                
                File.WriteAllBytes(path, key);

                KeyProvider.CurrentXXTEAKey = key;

                AddLog($"Generisan novi XXTEA ključ i sačuvan u {path}");
            }
            catch (Exception ex)
            {
                AddLog($"Greška pri generisanju ključa: {ex.Message}");
            }
        }
        private void cmbMode_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (tcpService != null && cmbMode.SelectedItem is ComboBoxItem item)
            {
                tcpService.SelectedMode = item.Content.ToString();
                AddLog($"Promenjen MODE na: {tcpService.SelectedMode}");
            }
        }
    }
}