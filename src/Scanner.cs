using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
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
    /// <remarks>
    /// Uses the Win32 file APIs directly so it also works on a volume that has no drive letter
    /// (\\?\Volume{guid}\ - how untrusted drives are kept); System.IO in .NET Framework rejects those paths.
    /// </remarks>
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

        const uint ATTR_HIDDEN = 0x2, ATTR_SYSTEM = 0x4, ATTR_DIRECTORY = 0x10, ATTR_REPARSE = 0x400;

        class Entry { public string Name; public uint Attr; public bool IsDir { get { return (Attr & ATTR_DIRECTORY) != 0; } } }

        public static ScanResult Scan(char letter) { return Scan(letter + @":\", letter + ":"); }

        /// <param name="root">"E:\" or "\\?\Volume{guid}\"</param>
        /// <param name="display">how the drive is named in the report</param>
        public static ScanResult Scan(string root, string display)
        {
            if (!root.EndsWith("\\")) root += "\\";
            var sb = new StringBuilder();
            bool sus = false;

            var label = new StringBuilder(261);
            var fs = new StringBuilder(261);
            uint serial, maxComp, flags;
            bool ready = false;
            for (int i = 0; i < 20 && !ready; i++)
            {
                ready = Native.GetVolumeInformationW(root, label, label.Capacity, out serial, out maxComp, out flags, fs, fs.Capacity);
                if (!ready) Thread.Sleep(250);
            }
            if (!ready)
                return new ScanResult { Report = "Drive " + display + " is not ready / could not be read.", Suspicious = false };

            ulong free, total, totalFree;
            string size = Native.GetDiskFreeSpaceExW(root, out free, out total, out totalFree) ? "  " + (total / (1024 * 1024)) + " MB" : "";
            sb.AppendLine("Drive " + display + "  label \"" + label + "\"  " + fs + size);

            // --- autorun.inf ---
            Entry autorun = List(root).FirstOrDefault(e => !e.IsDir && e.Name.Equals("autorun.inf", StringComparison.OrdinalIgnoreCase));
            if (autorun != null)
            {
                sus = true;
                sb.AppendLine();
                sb.AppendLine("!! AUTORUN.INF FOUND (" + (FileAttributes)autorun.Attr + ")");
                try
                {
                    string txt;
                    using (var h = Native.CreateFile(root + autorun.Name, 0x80000000 /*GENERIC_READ*/, 1 /*share read*/, IntPtr.Zero, 3 /*OPEN_EXISTING*/, 0, IntPtr.Zero))
                    {
                        if (h.IsInvalid) throw new IOException("error " + Marshal.GetLastWin32Error());
                        using (var st = new FileStream(h, FileAccess.Read))
                        using (var r = new StreamReader(st, true))
                        {
                            char[] b = new char[8192];
                            int n = r.Read(b, 0, b.Length);
                            txt = new string(b, 0, n);
                        }
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
            var queue = new Queue<KeyValuePair<string, int>>(); // relative folder ("" = root), depth
            queue.Enqueue(new KeyValuePair<string, int>("", 0));
            while (queue.Count > 0 && scanned < 5000)
            {
                var cur = queue.Dequeue();
                foreach (Entry e in List(root + cur.Key))
                {
                    string rel = cur.Key + e.Name;
                    if (e.IsDir)
                    {
                        if (cur.Value >= 2 || (e.Attr & ATTR_REPARSE) != 0) continue;
                        if (e.Name.Equals("System Volume Information", StringComparison.OrdinalIgnoreCase) || e.Name.Equals("$RECYCLE.BIN", StringComparison.OrdinalIgnoreCase)) continue;
                        queue.Enqueue(new KeyValuePair<string, int>(rel + "\\", cur.Value + 1));
                        continue;
                    }
                    scanned++;
                    if (e.Name.Equals("autorun.inf", StringComparison.OrdinalIgnoreCase)) continue;
                    string ext = Path.GetExtension(e.Name);
                    string inner = Path.GetExtension(Path.GetFileNameWithoutExtension(e.Name));
                    bool hidden = (e.Attr & (ATTR_HIDDEN | ATTR_SYSTEM)) != 0;
                    var why = new List<string>();
                    if (Risky.Contains(ext)) why.Add("executable/script");
                    if (Risky.Contains(ext) && Decoy.Contains(inner)) why.Add("DOUBLE EXTENSION");
                    if (cur.Value == 0 && ext.Equals(".lnk", StringComparison.OrdinalIgnoreCase)) why.Add("shortcut in root (USB worm trick)");
                    if (hidden && Risky.Contains(ext)) why.Add("hidden");
                    if (why.Count > 0) findings.Add(rel + "   <" + string.Join(", ", why) + ">");
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

        /// <summary>Files and folders directly in <paramref name="dir"/> (which ends with a backslash).</summary>
        static List<Entry> List(string dir)
        {
            var r = new List<Entry>();
            Native.WIN32_FIND_DATA d;
            IntPtr h = Native.FindFirstFileW(dir + "*", out d);
            if (h == new IntPtr(-1)) return r;
            try
            {
                do
                {
                    if (d.cFileName == "." || d.cFileName == "..") continue;
                    r.Add(new Entry { Name = d.cFileName, Attr = d.dwFileAttributes });
                } while (Native.FindNextFileW(h, out d));
            }
            finally { Native.FindClose(h); }
            return r;
        }
    }
}
