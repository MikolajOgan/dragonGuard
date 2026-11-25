using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;

namespace UsbGuard
{
    internal class ScanResult
    {
        public string Report;
        public bool Suspicious;
    }

    /// <summary>Looks for autorun.inf, executables/scripts, disguised shortcuts and double extensions on a drive.</summary>
    internal static class Scanner
    {
        static readonly HashSet<string> Risky = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".com", ".scr", ".pif", ".bat", ".cmd", ".ps1", ".psm1", ".psd1", ".vbs", ".vbe", ".js", ".jse",
            ".wsf", ".wsh", ".hta", ".lnk", ".msi", ".msp", ".jar", ".cpl", ".dll", ".reg", ".inf", ".scf", ".url",
            ".application", ".appref-ms", ".msc", ".gadget", ".settingcontent-ms", ".library-ms", ".iso", ".vhd", ".vhdx"
        };

        static readonly HashSet<string> Decoy = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".jpg", ".jpeg", ".png", ".gif",
            ".mp3", ".mp4", ".avi", ".zip", ".rar", ".7z"
        };

        public static ScanResult Scan(char letter)
        {
            string root = letter + @":\";
            var sb = new StringBuilder();
            bool sus = false;

            var di = new DriveInfo(root);
            for (int i = 0; i < 20 && !SafeReady(di); i++) Thread.Sleep(250);
            if (!SafeReady(di))
                return new ScanResult { Report = "Drive " + root + " is not ready / could not be read.", Suspicious = false };

            try
            {
                sb.AppendLine("Drive " + root + "  label \"" + di.VolumeLabel + "\"  " + di.DriveFormat + "  " +
                              (di.TotalSize / (1024 * 1024)) + " MB");
            }
            catch { sb.AppendLine("Drive " + root); }

            // --- autorun.inf ---
            string autorun = null;
            try { autorun = Directory.GetFiles(root, "autorun.inf").FirstOrDefault(); } catch { }
            if (autorun != null)
            {
                sus = true;
                sb.AppendLine();
                sb.AppendLine("!! AUTORUN.INF FOUND (" + Attr(autorun) + ")");
                try
                {
                    string txt;
                    using (var r = new StreamReader(autorun, true))
                    {
                        char[] b = new char[8192];
                        int n = r.Read(b, 0, b.Length);
                        txt = new string(b, 0, n);
                    }
                    foreach (string raw in txt.Split('\n'))
                    {
                        string line = raw.TrimEnd('\r');
                        string l = line.Trim().ToLowerInvariant();
                        bool exec = l.StartsWith("open") || l.StartsWith("shellexecute") || l.StartsWith("shell\\") ||
                                    l.StartsWith("action") || l.StartsWith("usellautoplay");
                        sb.AppendLine((exec ? "  >> " : "     ") + line);
                    }
                }
                catch (Exception ex) { sb.AppendLine("  (could not read: " + ex.Message + ")"); }
            }

            // --- files ---
            var findings = new List<string>();
            int scanned = 0;
            var queue = new Queue<KeyValuePair<string, int>>();
            queue.Enqueue(new KeyValuePair<string, int>(root, 0));
            while (queue.Count > 0 && scanned < 5000)
            {
                var cur = queue.Dequeue();
                string[] files = new string[0], dirs = new string[0];
                try { files = Directory.GetFiles(cur.Key); } catch { }
                try { dirs = Directory.GetDirectories(cur.Key); } catch { }

                foreach (string f in files)
                {
                    scanned++;
                    string name = Path.GetFileName(f);
                    string ext = Path.GetExtension(f);
                    string inner = Path.GetExtension(Path.GetFileNameWithoutExtension(f));
                    FileAttributes a = 0;
                    try { a = File.GetAttributes(f); } catch { }
                    bool hidden = (a & (FileAttributes.Hidden | FileAttributes.System)) != 0;
                    var why = new List<string>();
                    if (Risky.Contains(ext)) why.Add("executable/script");
                    if (Risky.Contains(ext) && Decoy.Contains(inner)) why.Add("DOUBLE EXTENSION");
                    if (cur.Value == 0 && ext.Equals(".lnk", StringComparison.OrdinalIgnoreCase)) why.Add("shortcut in root (USB worm trick)");
                    if (hidden && Risky.Contains(ext)) why.Add("hidden");
                    if (name.Equals("autorun.inf", StringComparison.OrdinalIgnoreCase)) continue;
                    if (why.Count > 0) findings.Add(f.Substring(root.Length) + "   <" + string.Join(", ", why) + ">");
                }
                if (cur.Value < 2)
                    foreach (string d in dirs)
                    {
                        string dn = Path.GetFileName(d);
                        if (dn.Equals("System Volume Information", StringComparison.OrdinalIgnoreCase) || dn == "$RECYCLE.BIN") continue;
                        queue.Enqueue(new KeyValuePair<string, int>(d, cur.Value + 1));
                    }
            }

            sb.AppendLine();
            if (findings.Count == 0)
                sb.AppendLine("No executables or scripts found in the top 3 folder levels (" + scanned + " files checked).");
            else
            {
                sus = true;
                sb.AppendLine("Executables / scripts found (" + findings.Count + ", " + scanned + " files checked):");
                foreach (string f in findings.Take(100)) sb.AppendLine("  " + f);
                if (findings.Count > 100) sb.AppendLine("  ... and " + (findings.Count - 100) + " more");
            }
            return new ScanResult { Report = sb.ToString(), Suspicious = sus };
        }

        static bool SafeReady(DriveInfo d)
        {
            try { return d.IsReady; } catch { return false; }
        }

        static string Attr(string f)
        {
            try { return File.GetAttributes(f).ToString(); } catch { return "?"; }
        }
    }
}
