using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Threading;

namespace CyberShieldLaptopLauncher
{
    static class Program
    {
        [STAThread]
        static void Main()
        {
            string baseDir = AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\');
            if (File.Exists(Path.Combine(baseDir, "laptop_desktop_app", "run_backend.py")))
            {
                baseDir = Path.Combine(baseDir, "laptop_desktop_app");
            }
            else if (!File.Exists(Path.Combine(baseDir, "run_backend.py")))
            {
                baseDir = @"C:\Users\gadup\Desktop\2.1 ADD\AI GEN\laptop_desktop_app";
            }
            Directory.SetCurrentDirectory(baseDir);

            string pythonExe = @"C:\Users\gadup\AppData\Local\Programs\Python\Python314\pythonw.exe";
            if (!File.Exists(pythonExe))
            {
                pythonExe = @"C:\Users\gadup\AppData\Local\Programs\Python\Python314\python.exe";
            }
            if (!File.Exists(pythonExe))
            {
                pythonExe = "pythonw.exe";
            }

            string appUrl = "http://127.0.0.1:8000";

            // 1. Ensure backend service is running on 0.0.0.0:8000
            if (!IsServerRunning(appUrl))
            {
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = pythonExe;
                psi.Arguments = "\"" + Path.Combine(baseDir, "run_backend.py") + "\"";
                psi.WorkingDirectory = baseDir;
                psi.CreateNoWindow = true;
                psi.UseShellExecute = false;
                psi.WindowStyle = ProcessWindowStyle.Hidden;

                try
                {
                    Process.Start(psi);
                }
                catch { }

                // Wait up to 5 seconds for backend to become responsive
                for (int i = 0; i < 25; i++)
                {
                    if (IsServerRunning(appUrl))
                    {
                        break;
                    }
                    Thread.Sleep(200);
                }
            }

            // 2. Locate browser executable (Chrome, Brave, or Edge)
            string browserPath = null;
            string[] candidateBrowsers = new string[]
            {
                @"C:\Program Files\Google\Chrome\Application\chrome.exe",
                @"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
                @"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
                @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                @"C:\Program Files\Microsoft\Edge\Application\msedge.exe"
            };

            foreach (string p in candidateBrowsers)
            {
                if (File.Exists(p))
                {
                    browserPath = p;
                    break;
                }
            }

            // 3. Launch dedicated standalone desktop window
            string profileDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "CyberShieldAI",
                "LaptopSOCProfile"
            );
            try
            {
                Directory.CreateDirectory(profileDir);
            }
            catch { }

            if (browserPath != null)
            {
                ProcessStartInfo bpsi = new ProcessStartInfo();
                bpsi.FileName = browserPath;
                bpsi.Arguments = string.Format(
                    "--app={0} --user-data-dir=\"{1}\" --no-first-run --no-default-browser-check --window-size=1440,900",
                    appUrl,
                    profileDir
                );
                bpsi.UseShellExecute = true;
                bpsi.WindowStyle = ProcessWindowStyle.Normal;

                try
                {
                    Process.Start(bpsi);
                }
                catch
                {
                    Process.Start(appUrl);
                }
            }
            else
            {
                Process.Start(appUrl);
            }
        }

        static bool IsServerRunning(string url)
        {
            try
            {
                HttpWebRequest req = (HttpWebRequest)WebRequest.Create(url + "/api/v1/stats");
                req.Timeout = 1500;
                req.Method = "GET";
                using (HttpWebResponse resp = (HttpWebResponse)req.GetResponse())
                {
                    return resp.StatusCode == HttpStatusCode.OK;
                }
            }
            catch
            {
                return false;
            }
        }
    }
}
