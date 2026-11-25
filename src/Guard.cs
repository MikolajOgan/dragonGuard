using System;
using System.Collections.Generic;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;

namespace UsbGuard
{
    internal enum DevState { Unknown, Allowed, Blocked }

    internal class DevEntry
    {
        public string Id, Name;
        public DevState State;
    }

    /// <summary>Shared state: allow/block lists, keyboard lockdown holds and the event log.</summary>
    internal static class Guard
    {
        public static readonly object Sync = new object();

        static readonly Dictionary<string, string> allowed = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        static readonly Dictionary<string, string> blocked = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        static readonly HashSet<string> sessionAllowed = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        static readonly HashSet<string> onceAllowed = new HashSet<string>(StringComparer.OrdinalIgnoreCase); // subset of sessionAllowed: until unplugged
        static readonly HashSet<string> holds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public static readonly Dictionary<int, string> DiskToPhys = new Dictionary<int, string>();

        /// <summary>When true the keyboard hook swallows every keystroke.</summary>
        public static volatile bool Lockdown;

        public static readonly string DataDir =
            Environment.GetEnvironmentVariable("USBGUARD_DATA") ??
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "UsbGuard");
        static readonly string ConfigPath = Path.Combine(DataDir, "devices.cfg");
        static readonly string LogPath = Path.Combine(DataDir, "usbguard.log");

        public static bool FirstRun;
        public static readonly List<string> LogLines = new List<string>();
        public static event Action<string> LogAdded;

        // ---------- lockdown ----------
        public static void Hold(string key)
        {
            lock (Sync) { holds.Add(key); Lockdown = true; }
        }

        /// <summary>Releases a keyboard and/or mouse hold with this key.</summary>
        public static void Release(string key)
        {
            lock (Sync)
            {
                holds.Remove(key); Lockdown = holds.Count > 0;
                mouseHolds.Remove(key); MouseLockdown = mouseHolds.Count > 0;
            }
        }

        static readonly HashSet<string> mouseHolds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        /// <summary>When true the mouse hook swallows all mouse input.</summary>
        public static volatile bool MouseLockdown;

        public static void HoldMouse(string key)
        {
            lock (Sync) { mouseHolds.Add(key); MouseLockdown = true; }
        }

        /// <summary>Config format version. v2 added mice/pointers and network adapters.</summary>
        public const int CurrentVersion = 2;
        public static int LoadedVersion = CurrentVersion;

        // ---------- lists ----------
        public static DevState GetState(string id)
        {
            lock (Sync)
            {
                if (blocked.ContainsKey(id)) return DevState.Blocked;
                if (allowed.ContainsKey(id) || sessionAllowed.Contains(id)) return DevState.Allowed;
                return DevState.Unknown;
            }
        }

        public static void Allow(string id, string name, bool remember)
        {
            lock (Sync)
            {
                blocked.Remove(id);
                onceAllowed.Remove(id);
                if (remember) { allowed[id] = name; sessionAllowed.Remove(id); } else sessionAllowed.Add(id);
            }
            Save();
        }

        /// <summary>Allowed only while it stays plugged in; asked again after it is unplugged.</summary>
        public static void AllowOnce(string id)
        {
            lock (Sync)
            {
                blocked.Remove(id);
                allowed.Remove(id);
                sessionAllowed.Add(id);
                onceAllowed.Add(id);
            }
            Save();
        }

        public static List<string> OnceAllowed()
        {
            lock (Sync) return new List<string>(onceAllowed);
        }

        /// <summary>Ends a one-time permission (the device was unplugged).</summary>
        public static bool EndOnce(string id)
        {
            lock (Sync)
            {
                if (!onceAllowed.Remove(id)) return false;
                sessionAllowed.Remove(id);
                return true;
            }
        }

        public static void Block(string id, string name)
        {
            lock (Sync)
            {
                allowed.Remove(id);
                sessionAllowed.Remove(id);
                onceAllowed.Remove(id);
                blocked[id] = name;
            }
            Save();
        }

        public static void Forget(string id)
        {
            lock (Sync) { allowed.Remove(id); blocked.Remove(id); sessionAllowed.Remove(id); onceAllowed.Remove(id); }
            Save();
        }

        public static List<DevEntry> Snapshot()
        {
            var l = new List<DevEntry>();
            lock (Sync)
            {
                foreach (var kv in allowed) l.Add(new DevEntry { Id = kv.Key, Name = kv.Value, State = DevState.Allowed });
                foreach (var id in sessionAllowed)
                    l.Add(new DevEntry { Id = id, Name = onceAllowed.Contains(id) ? "(once - until unplugged)" : "(until restart)", State = DevState.Allowed });
                foreach (var kv in blocked) l.Add(new DevEntry { Id = kv.Key, Name = kv.Value, State = DevState.Blocked });
            }
            return l;
        }

        // ---------- persistence ----------
        public static void Load()
        {
            EnsureDir();
            FirstRun = !File.Exists(ConfigPath);
            if (FirstRun) return;
            LoadedVersion = 1;
            lock (Sync)
            {
                foreach (string line in File.ReadAllLines(ConfigPath, Encoding.UTF8))
                {
                    string[] p = line.Split('\t');
                    if (p.Length < 2) continue;
                    int v;
                    if (p[0] == "V" && int.TryParse(p[1], out v)) { LoadedVersion = v; continue; }
                    string name = p.Length > 2 ? p[2] : "";
                    if (p[0] == "A") allowed[p[1]] = name;
                    else if (p[0] == "B") blocked[p[1]] = name;
                }
            }
        }

        /// <summary>True in the service process: it owns and persists the device lists and the log file.</summary>
        public static bool IsService;

        /// <summary>Agent: sends a log line to the service; returns false if not connected.</summary>
        public static Func<string, bool> RemoteLog;

        /// <summary>Agent: mirror of the service's lists ('A' allowed, 'S' session-allowed, 'O' allowed once, 'B' blocked, '-' none).</summary>
        public static void SetMirror(string id, string name, char st)
        {
            lock (Sync)
            {
                allowed.Remove(id); blocked.Remove(id); sessionAllowed.Remove(id); onceAllowed.Remove(id);
                if (st == 'A') allowed[id] = name;
                else if (st == 'B') blocked[id] = name;
                else if (st == 'S') sessionAllowed.Add(id);
                else if (st == 'O') { sessionAllowed.Add(id); onceAllowed.Add(id); }
            }
        }

        public static char StateChar(string id)
        {
            lock (Sync)
            {
                if (blocked.ContainsKey(id)) return 'B';
                if (allowed.ContainsKey(id)) return 'A';
                if (onceAllowed.Contains(id)) return 'O';
                if (sessionAllowed.Contains(id)) return 'S';
                return '-';
            }
        }

        public static string NameOf(string id)
        {
            lock (Sync)
            {
                string n;
                if (allowed.TryGetValue(id, out n) || blocked.TryGetValue(id, out n)) return n;
                return "";
            }
        }

        /// <summary>Agent fallback when the service is unreachable: read the (world-readable) list file.</summary>
        public static void LoadMirrorFromFile()
        {
            try { if (File.Exists(ConfigPath)) Load(); } catch { }
        }

        /// <summary>Agent: a log line that came from the service.</summary>
        public static void AddRemoteLine(string line)
        {
            lock (LogLines)
            {
                LogLines.Add(line);
                if (LogLines.Count > 2000) LogLines.RemoveRange(0, 500);
            }
            var h = LogAdded;
            if (h != null) { try { h(line); } catch { } }
        }

        public static void Save()
        {
            if (!IsService) return;
            var sb = new StringBuilder();
            sb.AppendLine("# UsbGuard device list: A=allowed, B=blocked. <state>\\t<device instance id>\\t<name>");
            sb.AppendLine("V\t" + CurrentVersion);
            lock (Sync)
            {
                foreach (var kv in allowed) sb.AppendLine("A\t" + kv.Key + "\t" + Clean(kv.Value));
                foreach (var kv in blocked) sb.AppendLine("B\t" + kv.Key + "\t" + Clean(kv.Value));
            }
            try
            {
                EnsureDir();
                string tmp = ConfigPath + ".tmp";
                File.WriteAllText(tmp, sb.ToString(), Encoding.UTF8);
                if (File.Exists(ConfigPath)) File.Replace(tmp, ConfigPath, null);
                else File.Move(tmp, ConfigPath);
            }
            catch (Exception ex) { Log("Could not save device list: " + ex.Message); }
        }

        static string Clean(string s)
        {
            return (s ?? "").Replace('\t', ' ').Replace('\r', ' ').Replace('\n', ' ');
        }

        static void EnsureDir()
        {
            if (Directory.Exists(DataDir)) return;
            Directory.CreateDirectory(DataDir);
            if (Environment.GetEnvironmentVariable("USBGUARD_DATA") != null) return; // test mode: keep default ACL
            try
            {
                // Only admins/SYSTEM may change the allow list; users can read it.
                var ds = new DirectorySecurity();
                ds.SetAccessRuleProtection(true, false);
                var inh = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
                ds.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                    FileSystemRights.FullControl, inh, PropagationFlags.None, AccessControlType.Allow));
                ds.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                    FileSystemRights.FullControl, inh, PropagationFlags.None, AccessControlType.Allow));
                ds.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
                    FileSystemRights.ReadAndExecute, inh, PropagationFlags.None, AccessControlType.Allow));
                Directory.SetAccessControl(DataDir, ds);
            }
            catch { }
        }

        // ---------- log ----------
        public static void Log(string msg)
        {
            // Agent: the service writes the file and echoes the line back to every agent.
            if (!IsService)
            {
                var r = RemoteLog;
                if (r != null && r(msg)) return;
            }
            string line = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "  " + msg;
            lock (LogLines)
            {
                LogLines.Add(line);
                if (LogLines.Count > 2000) LogLines.RemoveRange(0, 500);
                if (IsService) try
                {
                    var fi = new FileInfo(LogPath);
                    if (fi.Exists && fi.Length > 5 * 1024 * 1024) File.Delete(LogPath);
                    File.AppendAllText(LogPath, line + Environment.NewLine, Encoding.UTF8);
                }
                catch { }
            }
            var h = LogAdded;
            if (h != null) { try { h(line); } catch { } }
        }

        public static string LogFile { get { return LogPath; } }
    }
}
