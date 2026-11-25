using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.ServiceProcess;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;

namespace UsbGuard
{
    /// <summary>
    /// Tray agent in the user's session: approval windows, keyboard/mouse lock, drive scans.
    /// Device control is done by the service (pipe); if the service is unreachable the agent
    /// falls back to doing it itself (it runs elevated or as SYSTEM).
    /// </summary>
    internal class App : ApplicationContext, IDeviceSink
    {
        readonly Control invoker;
        readonly NotifyIcon tray;
        readonly Dictionary<string, PromptForm> pending = new Dictionary<string, PromptForm>(StringComparer.OrdinalIgnoreCase);
        readonly List<PromptForm> order = new List<PromptForm>();
        readonly Dictionary<string, KeyValuePair<char, ScanResult>> lateScans = new Dictionary<string, KeyValuePair<char, ScanResult>>(StringComparer.OrdinalIgnoreCase);
        // Drives without a letter (kept locked until approval) whose approval window isn't open yet: phys -> volumes.
        readonly Dictionary<string, HashSet<string>> lateVolumes = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        // Volumes whose letter this agent removed itself (service not reachable): volume -> phys.
        readonly Dictionary<string, string> localLocked = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        readonly HashSet<string> kbServiceDisabled = new HashSet<string>(StringComparer.OrdinalIgnoreCase); // keyboard switched off by service
        readonly HashSet<string> kbEnabled = new HashSet<string>(StringComparer.OrdinalIgnoreCase);         // switched on for arrow approval
        readonly Dictionary<string, System.Windows.Forms.Timer> awaiting = new Dictionary<string, System.Windows.Forms.Timer>(StringComparer.OrdinalIgnoreCase);
        readonly System.Windows.Forms.Timer unplugTimer, trayTimer, focusTimer;
        static readonly uint OwnPid = (uint)Process.GetCurrentProcess().Id;
        IntPtr trayWnd;
        public readonly PipeClient Client = new PipeClient();
        public readonly ManualResetEvent Synced = new ManualResetEvent(false);
        public readonly bool AdminMode;   // false when running as SYSTEM for a standard user
        bool locked;
        LogForm logForm;
        DevicesForm devForm;
        ToolStripMenuItem miHarden, miNetPolicy, miNetHarden;

        public App()
        {
            invoker = new Control();
            IntPtr force = invoker.Handle; // create handle on the UI thread
            AdminMode = !WindowsIdentity.GetCurrent().IsSystem;

            var menu = new ContextMenuStrip();
            menu.Items.Add("Event log...", null, (s, e) => ShowLog());
            menu.Items.Add("Allowed / blocked devices...", null, (s, e) => ShowDevices());
            menu.Items.Add("Test the approval window", null, (s, e) => StartTest());
            if (AdminMode)
            {
                menu.Items.Add(new ToolStripSeparator());
                miHarden = new ToolStripMenuItem("Disable Windows AutoRun / AutoPlay", null, (s, e) => ToggleHarden());
                miNetPolicy = new ToolStripMenuItem("Windows policy: refuse to install new USB network adapters", null, (s, e) => ToggleNetPolicy());
                miNetHarden = new ToolStripMenuItem("Network hardening (LLMNR / NetBIOS / WPAD off, SMB signing)", null, (s, e) => ToggleNetHardening());
                menu.Items.Add(miHarden);
                menu.Items.Add(miNetPolicy);
                menu.Items.Add(miNetHarden);
                menu.Items.Add(new ToolStripSeparator());
                menu.Items.Add("Uninstall DragonGuard...", null, (s, e) => UninstallFromTray());
                menu.Opening += (s, e) =>
                {
                    miHarden.Checked = Hardening.IsEnabled();
                    miNetPolicy.Checked = DeviceInstallPolicy.IsEnabled();
                    miNetHarden.Checked = NetHardening.IsEnabled();
                };
            }

            tray = new NotifyIcon
            {
                Icon = Branding.SmallIcon, Text = "DragonGuard - connecting to service...", ContextMenuStrip = menu, Visible = true
            };
            tray.DoubleClick += (s, e) => ShowLog();

            // We run elevated (or as SYSTEM). UIPI drops Explorer's "TaskbarCreated" broadcast to higher-integrity
            // processes, so the icon was lost when we started before the taskbar existed (at logon) or Explorer restarted.
            try { Native.ChangeWindowMessageFilter(Native.RegisterWindowMessage("TaskbarCreated"), Native.MSGFLT_ADD); } catch { }
            // Belt and braces: re-add the icon whenever a (new) taskbar window appears.
            trayTimer = new System.Windows.Forms.Timer { Interval = 3000 };
            trayTimer.Tick += (s, e) =>
            {
                IntPtr h = Native.FindWindow("Shell_TrayWnd", null);
                if (h != IntPtr.Zero && h != trayWnd) { tray.Visible = false; tray.Visible = true; }
                trayWnd = h;
            };
            trayTimer.Start();

            // Real unplugs (a switched-off function also removes its interface, so we check the device itself).
            unplugTimer = new System.Windows.Forms.Timer { Interval = 1000 };
            unplugTimer.Tick += (s, e) =>
            {
                foreach (var f in order.ToList())
                    if (!f.IsTest && Dev.Locate(f.Phys) == 0)
                    {
                        Guard.Log("Device unplugged " + (f.IsDecided ? "" : "before a decision") + ": " + f.DevName + CapturedSuffix(f));
                        Close(f);
                    }
                // Without the service nobody else ends "allow once" permissions.
                if (!Client.IsConnected)
                    foreach (string id in Guard.OnceAllowed())
                        if (Dev.Locate(id) == 0) Guard.EndOnce(id);
            };
            unplugTimer.Start();

            // While the keyboard is locked, none of our windows may stay the active window (see KeepFocusAway).
            focusTimer = new System.Windows.Forms.Timer { Interval = 150 };
            focusTimer.Tick += (s, e) => KeepFocusAway();
            focusTimer.Start();

            SystemEvents.SessionSwitch += OnSessionSwitch;

            // ---- service connection ----
            Guard.RemoteLog = msg => Client.Send("LOG", msg);
            Client.Connected += () => { Client.Send("HELLO"); Post(() => tray.Text = "DragonGuard - protecting (service connected)"); };
            Client.Disconnected += () =>
            {
                Post(() =>
                {
                    kbEnabled.Clear(); // the service switches them off again when we disconnect
                    tray.Text = "DragonGuard - SERVICE NOT REACHABLE";
                    tray.ShowBalloonTip(5000, "DragonGuard", "The DragonGuard service is not reachable. Protection is limited to this session.", ToolTipIcon.Warning);
                });
            };
            Client.Message += OnServiceMessage;
        }

        public void Post(Action a)
        {
            try { if (!invoker.IsDisposed) invoker.BeginInvoke(a); } catch { }
        }

        public void Balloon(string title, string text, ToolTipIcon icon)
        {
            tray.ShowBalloonTip(5000, title, text, icon);
        }

        /// <summary>
        /// Keystrokes sent to a window of our own process could get past the low-level hook: the capture stayed
        /// empty and e.g. Ctrl+Shift+Esc still opened Task Manager. That happened right after the tray menu /
        /// a message box made one of our windows the active one. During a keyboard lock we hand the active window
        /// to the taskbar, where the hook reliably swallows and records every key.
        /// </summary>
        void KeepFocusAway()
        {
            if (!Guard.Lockdown) return;
            if (tray.ContextMenuStrip != null && tray.ContextMenuStrip.Visible) return; // keep the tray menu usable
            IntPtr fg = Native.GetForegroundWindow();
            if (fg == IntPtr.Zero) return;
            uint pid;
            Native.GetWindowThreadProcessId(fg, out pid);
            if (pid != OwnPid) return;
            IntPtr target = Native.FindWindow("Shell_TrayWnd", null);
            if (target == IntPtr.Zero) target = Native.GetShellWindow();
            if (target != IntPtr.Zero) Native.SetForegroundWindow(target);
        }

        static bool IsConsoleSession()
        {
            return (uint)Process.GetCurrentProcess().SessionId == Native.WTSGetActiveConsoleSessionId();
        }

        // ================= service messages (reader thread) =================
        void OnServiceMessage(string[] m)
        {
            switch (m[0])
            {
                case "STATE":   // handled right here so the mirror is complete before SYNCED
                    if (m.Length >= 4 && m[3].Length > 0) Guard.SetMirror(m[1], m[2], m[3][0]);
                    Post(() => { if (devForm != null && !devForm.IsDisposed) devForm.Reload(); });
                    break;
                case "SYNCED":
                    Synced.Set();
                    break;
                case "LOG":
                    if (m.Length > 1) Guard.AddRemoteLine(m[1]);
                    break;
                case "PENDING":
                    if (m.Length < 8) break;
                    IfaceKind kind;
                    if (!Enum.TryParse(m[2], out kind)) break;
                    var ev = new DeviceEvent
                    {
                        Phys = m[1], Kind = kind, Path = m[3], Name = m[4],
                        DisabledInst = m[5] == "1" ? m[6] : null, Note = m[7].Length > 0 ? m[7] : null,
                        MouseHeld = m.Length > 8 && m[8] == "1"
                    };
                    if (kind == IfaceKind.Keyboard) Guard.Hold(ev.Phys); // lock before anything else
                    Post(() => OnServicePending(ev));
                    break;
                case "DECIDED":
                    if (m.Length >= 4) { string p = m[1], st = m[2], err = m[3]; Post(() => OnServiceDecided(p, st == "A", err)); }
                    break;
                case "VOLUME":  // VOLUME phys \\?\Volume{guid}\  - drive kept without a letter until approval
                    if (m.Length >= 3) { string p = m[1], v = m[2]; Post(() => OnLockedVolume(p, v)); }
                    break;
                case "GONE":
                    if (m.Length >= 2) { string p = m[1]; Post(() => { PromptForm f; if (pending.TryGetValue(p, out f)) { Guard.Log("Device unplugged before a decision: " + f.DevName + CapturedSuffix(f)); Close(f); } }); }
                    break;
            }
        }

        void OnServicePending(DeviceEvent ev)
        {
            OnArrived(ev);
            if (ev.Kind == IfaceKind.Keyboard && ev.DisabledInst != null)
            {
                kbServiceDisabled.Add(ev.Phys);
                RequestKbEnable(ev.Phys);
            }
        }

        /// <summary>Lock all keyboards, then let the service switch the new keyboard on so its arrow keys can approve it.</summary>
        void RequestKbEnable(string phys)
        {
            if (locked || !IsConsoleSession() || kbEnabled.Contains(phys)) return;
            PromptForm f;
            if (!pending.TryGetValue(phys, out f) || f.IsDecided) return;
            Guard.Hold(phys);
            if (Client.Send("ENABLE_KB", phys)) kbEnabled.Add(phys);
        }

        void OnSessionSwitch(object sender, SessionSwitchEventArgs e)
        {
            Post(() =>
            {
                if (e.Reason == SessionSwitchReason.SessionLock || e.Reason == SessionSwitchReason.ConsoleDisconnect)
                {
                    // Our hook does not work on the lock screen: switch pending keyboards off again.
                    locked = true;
                    foreach (string p in kbEnabled) Client.Send("DISABLE_KB", p);
                    kbEnabled.Clear();
                }
                else if (e.Reason == SessionSwitchReason.SessionUnlock || e.Reason == SessionSwitchReason.ConsoleConnect)
                {
                    locked = false;
                    foreach (string p in kbServiceDisabled.ToList()) RequestKbEnable(p);
                }
            });
        }

        void OnServiceDecided(string phys, bool allow, string err)
        {
            System.Windows.Forms.Timer t;
            if (awaiting.TryGetValue(phys, out t)) { t.Dispose(); awaiting.Remove(phys); }
            PromptForm f;
            if (!pending.TryGetValue(phys, out f)) return;
            if (string.IsNullOrEmpty(err))
            {
                if (!allow) Balloon("DragonGuard", "Device blocked: " + f.DevName, ToolTipIcon.Info);
                if (f.CapturedText.Length > 0) Guard.Log("Blocked actions while " + f.DevName + " was pending:" + CapturedSuffix(f));
                Close(f);
            }
            else
            {
                f.ShowDisableFailed(err);
                if (!f.NeedsArrows) Guard.Release(phys);
            }
        }

        // ================= IDeviceSink (local watcher thread) =================
        public void InterfaceArrived(DeviceEvent e) { Post(() => OnArrived(e)); }
        public void VolumeArrived(char letter, string phys) { Post(() => OnVolume(letter, phys)); }

        // ================= UI thread =================
        void OnArrived(DeviceEvent e)
        {
            PromptForm f;
            if (!pending.TryGetValue(e.Phys, out f))
            {
                f = new PromptForm(e.Phys, e.Name, e.IsTest);
                f.Decided += OnDecided;
                f.UnlockRequested += p => { Guard.Release(p.Phys); Guard.Log("User unlocked keyboard/mouse manually (" + p.DevName + ")"); };
                pending[e.Phys] = f;
                order.Add(f);
                f.Show();
                if (e.Kind == IfaceKind.Network || e.Kind == IfaceKind.Pointer)
                    Balloon("DragonGuard", "New " + (e.Kind == IfaceKind.Network ? "USB network adapter" : "mouse/pointer") + " was switched off until you approve it: " + e.Name, ToolTipIcon.Warning);
                KeyValuePair<char, ScanResult> late;
                if (lateScans.TryGetValue(e.Phys, out late)) { lateScans.Remove(e.Phys); f.AddDrive(late.Key + ":"); f.SetScan(late.Key + ":", late.Value); }
                HashSet<string> vols;
                if (lateVolumes.TryGetValue(e.Phys, out vols)) { lateVolumes.Remove(e.Phys); foreach (string v in vols) ScanLockedVolume(f, v); }
            }
            if (e.MouseHeld) { Guard.HoldMouse(e.Phys); Guard.Hold(e.Phys); }
            f.AddInterface(e);
            UpdateActive();
            KeepFocusAway();
        }

        /// <summary>A drive of an untrusted device that has no drive letter: show it in its window and scan it.</summary>
        void OnLockedVolume(string phys, string vol)
        {
            PromptForm f;
            if (pending.TryGetValue(phys, out f)) { ScanLockedVolume(f, vol); return; }
            if (Guard.GetState(phys) == DevState.Blocked) return;
            HashSet<string> set;
            if (!lateVolumes.TryGetValue(phys, out set)) lateVolumes[phys] = set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            set.Add(vol);
        }

        void ScanLockedVolume(PromptForm f, string vol)
        {
            const string display = "no drive letter until allowed";
            if (!f.AddDrive(display, true)) return; // already scanned
            RunScan(() => Scanner.Scan(vol, "(" + display + ")"), r =>
            {
                if (!f.IsDisposed) f.SetScan(display, r);
                if (r.Suspicious) Guard.Log("Scan: suspicious content on the drive of pending device " + f.DevName);
            });
        }

        void OnVolume(char letter, string phys)
        {
            DevState st = phys == null ? DevState.Allowed : Guard.GetState(phys);
            if (st == DevState.Blocked) return;
            if (st != DevState.Allowed)
            {
                // Not trusted (yet): the drive must not be usable. The service removes the letter and sends VOLUME;
                // without the service we do it ourselves (we run elevated / as SYSTEM).
                if (Client.IsConnected) return;
                string vol = Volumes.NameOf(letter + @":\");
                if (vol != null && Volumes.HideLetters(vol).Length > 0)
                {
                    localLocked[vol] = phys;
                    Guard.Log("Removed drive letter " + letter + ": of untrusted USB drive until approval (service not reachable)  [" + phys + "]");
                    OnLockedVolume(phys, vol);
                    return;
                }
            }
            PromptForm f;
            if (phys != null && pending.TryGetValue(phys, out f))
            {
                string d = letter + ":";
                f.AddDrive(d);
                RunScan(letter, r => { if (!f.IsDisposed) f.SetScan(d, r); if (r.Suspicious) Guard.Log("Scan " + letter + ": suspicious content on pending device " + f.DevName); });
                return;
            }
            bool removable = false;
            try { removable = new DriveInfo(letter + ":\\").DriveType == DriveType.Removable; } catch { }
            if (phys == null && !removable) return;

            RunScan(letter, r =>
            {
                PromptForm pf;
                if (phys != null && pending.TryGetValue(phys, out pf)) { pf.AddDrive(letter + ":"); pf.SetScan(letter + ":", r); return; }
                if (phys != null && Guard.GetState(phys) == DevState.Unknown) { lateScans[phys] = new KeyValuePair<char, ScanResult>(letter, r); return; }
                if (!r.Suspicious) return;
                Guard.Log("Suspicious content on drive " + letter + ": (allowed device)\r\n" + r.Report);
                Balloon("DragonGuard - drive " + letter + ": looks suspicious",
                        "autorun.inf or executables/scripts were found. Double-click the DragonGuard tray icon for details.", ToolTipIcon.Warning);
            });
        }

        void RunScan(char letter, Action<ScanResult> done)
        {
            RunScan(() => Scanner.Scan(letter), done);
        }

        void RunScan(Func<ScanResult> scan, Action<ScanResult> done)
        {
            ThreadPool.QueueUserWorkItem(_ =>
            {
                ScanResult r;
                try { r = scan(); }
                catch (Exception ex) { r = new ScanResult { Report = "Scan failed: " + ex.Message }; }
                Post(() => done(r));
            });
        }

        PromptForm ActivePrompt()
        {
            return order.FirstOrDefault(p => p.NeedsArrows && !p.IsDecided);
        }

        void UpdateActive()
        {
            PromptForm act = ActivePrompt();
            foreach (var p in order) p.SetActive(p == act);
        }

        public void OnKey(KeyRecord r)
        {
            PromptForm act = ActivePrompt();
            if (act != null) act.OnKey(r);
        }

        public void OnMouse(MouseRecord r)
        {
            PromptForm act = order.FirstOrDefault(p => p.HasPointer && !p.IsDecided) ?? order.FirstOrDefault(p => !p.IsDecided);
            if (act != null) act.OnMouse(r);
        }

        void OnDecided(PromptForm f, bool allow, string mode)
        {
            string phys = f.Phys;
            if (f.IsTest)
            {
                Guard.Log("Test window: " + (allow ? "approved" : "blocked") + CapturedSuffix(f));
                Close(f);
                return;
            }
            if (allow && f.CapturedText.Length > 0) Guard.Log("Blocked actions before approval of " + f.DevName + ":" + CapturedSuffix(f));

            if (Client.Send(allow ? "ALLOW" : "BLOCK", phys, f.DevName, mode))
            {
                // Keep everything locked until the service confirms (a blocked keyboard must be off first).
                var t = new System.Windows.Forms.Timer { Interval = 8000 };
                t.Tick += (s, e) => { t.Dispose(); awaiting.Remove(phys); LocalDecide(f, allow, mode, "service did not answer"); };
                awaiting[phys] = t;
                t.Start();
            }
            else LocalDecide(f, allow, mode, "service not reachable");
        }

        /// <summary>Fallback when the service is gone: do it ourselves (we are elevated / SYSTEM).</summary>
        void LocalDecide(PromptForm f, bool allow, string mode, string why)
        {
            string phys = f.Phys;
            bool remember = mode == "1";
            if (allow)
            {
                Guard.SetMirror(phys, f.DevName, mode == "O" ? 'O' : 'S');
                foreach (string inst in f.ToEnable) Dev.EnableInstance(inst);
                foreach (var kv in localLocked.Where(x => string.Equals(x.Value, phys, StringComparison.OrdinalIgnoreCase)).ToList())
                {
                    localLocked.Remove(kv.Key);
                    Volumes.GiveLetter(kv.Key);
                }
                Guard.Log("ALLOWED locally (" + why + "): " + f.DevName);
                Close(f);
                return;
            }
            ThreadPool.QueueUserWorkItem(_ =>
            {
                string err = Dev.DisableOrRemove(phys);
                Post(() =>
                {
                    Guard.Log("BLOCK locally (" + why + "): " + f.DevName + (err == null ? " disabled" : " - " + err));
                    if (err == null) { if (remember) Guard.SetMirror(phys, f.DevName, 'B'); Close(f); }
                    else { f.ShowDisableFailed(err); if (!f.NeedsArrows) Guard.Release(phys); }
                });
            });
        }

        static string CapturedSuffix(PromptForm f)
        {
            string c = f.CapturedText;
            if (string.IsNullOrEmpty(c)) return "";
            if (c.Length > 2000) c = c.Substring(0, 2000) + "...";
            return "\r\n    Blocked keystrokes/mouse actions: " + c.Replace("\r\n", "\r\n    ");
        }

        void Close(PromptForm f)
        {
            pending.Remove(f.Phys);
            order.Remove(f);
            kbServiceDisabled.Remove(f.Phys);
            kbEnabled.Remove(f.Phys);
            System.Windows.Forms.Timer t;
            if (awaiting.TryGetValue(f.Phys, out t)) { t.Dispose(); awaiting.Remove(f.Phys); }
            Guard.Release(f.Phys);
            if (!f.IsDisposed) { f.Hide(); f.Dispose(); }
            UpdateActive();
        }

        void StartTest()
        {
            const string id = @"TEST\SIMULATED_KEYBOARD";
            if (pending.ContainsKey(id)) return;
            if (MessageBox.Show("This simulates a new keyboard: ALL keyboard input will be blocked until you enter the arrow sequence or click Block.\r\n\r\nContinue?",
                "DragonGuard test", MessageBoxButtons.OKCancel, MessageBoxIcon.Information) != DialogResult.OK) return;
            Guard.Hold(id);
            OnArrived(new DeviceEvent { Phys = id, Name = "Simulated keyboard (test)", Kind = IfaceKind.Keyboard, Path = "test", IsTest = true });
        }

        void ShowLog()
        {
            if (logForm == null || logForm.IsDisposed) logForm = new LogForm(this);
            logForm.Show(); logForm.Activate();
        }

        void ShowDevices()
        {
            if (devForm == null || devForm.IsDisposed) devForm = new DevicesForm(this);
            devForm.Reload(); devForm.Show(); devForm.Activate();
        }

        void ToggleHarden()
        {
            try
            {
                bool on = !Hardening.IsEnabled();
                Hardening.Set(on);
                Guard.Log("Windows AutoRun/AutoPlay " + (on ? "disabled (hardened)" : "restored to default"));
            }
            catch (Exception ex) { MessageBox.Show("Failed: " + ex.Message, "DragonGuard"); }
        }

        void ToggleNetPolicy()
        {
            try
            {
                if (DeviceInstallPolicy.IsEnabled()) { DeviceInstallPolicy.Disable(); return; }
                var keep = DeviceInstallPolicy.CurrentUsbAdapters();
                if (MessageBox.Show(
                    "Windows will refuse to install drivers for NEW USB network adapters (RNDIS / CDC Ethernet), " +
                    "the kind used by LAN Turtle, PoisonTap, Bash Bunny, P4wnP1.\r\n\r\n" +
                    "Adapters connected right now stay allowed (" + keep.Count + " found). Phone USB tethering and new USB " +
                    "Ethernet dongles will NOT work while this is on - switch it off temporarily to add one.\r\n\r\nEnable?",
                    "DragonGuard", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
                DeviceInstallPolicy.Enable();
            }
            catch (Exception ex) { MessageBox.Show("Failed: " + ex.Message, "DragonGuard"); }
        }

        void ToggleNetHardening()
        {
            try
            {
                if (NetHardening.IsEnabled()) { NetHardening.Disable(); MessageBox.Show("Original network settings restored. Reboot to apply fully.", "DragonGuard"); return; }
                if (MessageBox.Show(
                    "This removes what rogue network adapters abuse to steal your Windows password hash or hijack traffic:\r\n\r\n" +
                    " • LLMNR name resolution off\r\n" +
                    " • NetBIOS name broadcasts off (P-node) and NetBIOS over TCP/IP off on current adapters\r\n" +
                    " • WinHTTP automatic proxy discovery (WPAD) off\r\n" +
                    " • SMB client requires signing (blocks NTLM relay)\r\n" +
                    " • Firewall: Public / unidentified networks block ALL inbound connections\r\n\r\n" +
                    "Possible side effects: very old NAS/SMB servers without signing, or finding PCs by NetBIOS name on old networks. " +
                    "Original values are saved and restored when you switch this off.\r\n\r\nEnable? (reboot recommended afterwards)",
                    "DragonGuard", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
                NetHardening.Enable();
            }
            catch (Exception ex) { MessageBox.Show("Failed: " + ex.Message, "DragonGuard"); }
        }

        void UninstallFromTray()
        {
            if (MessageBox.Show("Uninstall the DragonGuard service? New USB keyboards, mice, network adapters and drives will no longer be checked.\r\n\r\n" +
                "Your device lists and the network/policy settings are kept (switch those off first if you want them removed).",
                "DragonGuard", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
            try
            {
                // Run from a temp copy so the program folder can be deleted.
                string tmp = Path.Combine(Path.GetTempPath(), "UsbGuard_uninstall.exe");
                File.Copy(Application.ExecutablePath, tmp, true);
                Process.Start(new ProcessStartInfo(tmp, "--uninstall") { UseShellExecute = false });
            }
            catch (Exception ex) { MessageBox.Show("Failed: " + ex.Message, "DragonGuard"); }
        }
    }

    // =====================================================================
    internal class LogForm : Form
    {
        readonly TextBox box;
        readonly Action<string> handler;

        public LogForm(App app)
        {
            Text = "DragonGuard - event log";
            Icon = Branding.Icon;
            Size = new Size(900, 520);
            StartPosition = FormStartPosition.CenterScreen;
            box = new TextBox { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = false, Dock = DockStyle.Fill, Font = new Font("Consolas", 9.5F), BackColor = Color.White };
            var info = new Label { Dock = DockStyle.Bottom, AutoSize = false, Height = 22, Text = "  Full log: " + Guard.LogFile, TextAlign = ContentAlignment.MiddleLeft };
            Controls.Add(box);
            Controls.Add(info);
            lock (Guard.LogLines) box.Text = string.Join("\r\n", Guard.LogLines) + "\r\n";
            handler = line => app.Post(() => { if (!IsDisposed) box.AppendText(line.Replace("\n", "\r\n").Replace("\r\r", "\r") + "\r\n"); });
            Guard.LogAdded += handler;
            FormClosed += (s, e) => Guard.LogAdded -= handler;
            Shown += (s, e) => { box.SelectionStart = box.TextLength; box.ScrollToCaret(); };
        }
    }

    internal class DevicesForm : Form
    {
        readonly ListView list;
        readonly App app;

        public DevicesForm(App app)
        {
            this.app = app;
            Text = "DragonGuard - devices";
            Icon = Branding.Icon;
            Size = new Size(900, 420);
            StartPosition = FormStartPosition.CenterScreen;
            list = new ListView { View = View.Details, FullRowSelect = true, Dock = DockStyle.Fill, MultiSelect = false };
            list.Columns.Add("State", 80);
            list.Columns.Add("Name", 280);
            list.Columns.Add("Device instance ID", 500);
            Controls.Add(list);
            if (app.AdminMode)
            {
                var bar = new FlowLayoutPanel { Dock = DockStyle.Bottom, AutoSize = true, FlowDirection = FlowDirection.RightToLeft };
                var bForget = new Button { Text = "Forget (ask again next time)", AutoSize = true };
                var bBlock = new Button { Text = "Block", AutoSize = true };
                var bAllow = new Button { Text = "Allow", AutoSize = true };
                bar.Controls.AddRange(new Control[] { bForget, bBlock, bAllow });
                Controls.Add(bar);
                bForget.Click += (s, e) => Act(d => app.Client.Send("FORGET", d.Id));
                bBlock.Click += (s, e) => Act(d => app.Client.Send("SETSTATE", d.Id, d.Name, "B"));
                bAllow.Click += (s, e) => Act(d => app.Client.Send("SETSTATE", d.Id, d.Name, "A"));
            }
        }

        void Act(Func<DevEntry, bool> a)
        {
            if (list.SelectedItems.Count == 0) return;
            if (!a((DevEntry)list.SelectedItems[0].Tag))
                MessageBox.Show("The DragonGuard service is not reachable.", "DragonGuard");
        }

        public void Reload()
        {
            list.Items.Clear();
            foreach (var d in Guard.Snapshot().OrderBy(x => x.State).ThenBy(x => x.Name))
            {
                var it = new ListViewItem(new[] { d.State.ToString(), d.Name, d.Id }) { Tag = d };
                if (d.State == DevState.Blocked) it.ForeColor = Color.DarkRed;
                list.Items.Add(it);
            }
        }
    }

    // =====================================================================
    internal static class Hardening
    {
        const string PolKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";
        const string ApKey = @"Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers";

        public static bool IsEnabled()
        {
            try
            {
                using (var k = Registry.LocalMachine.OpenSubKey(PolKey))
                using (var a = Registry.CurrentUser.OpenSubKey(ApKey))
                {
                    object v1 = k == null ? null : k.GetValue("NoDriveTypeAutoRun");
                    object v2 = a == null ? null : a.GetValue("DisableAutoplay");
                    return v1 is int && (int)v1 == 0xFF && v2 is int && (int)v2 == 1;
                }
            }
            catch { return false; }
        }

        public static void Set(bool on)
        {
            using (var k = Registry.LocalMachine.CreateSubKey(PolKey))
            {
                if (on) { k.SetValue("NoDriveTypeAutoRun", 0xFF, RegistryValueKind.DWord); k.SetValue("NoAutorun", 1, RegistryValueKind.DWord); }
                else { k.DeleteValue("NoDriveTypeAutoRun", false); k.DeleteValue("NoAutorun", false); }
            }
            using (var a = Registry.CurrentUser.CreateSubKey(ApKey))
                a.SetValue("DisableAutoplay", on ? 1 : 0, RegistryValueKind.DWord);
        }
    }

    // =====================================================================
    internal static class Program
    {
        [STAThread]
        static int Main(string[] args)
        {
            string mode = args.Length > 0 ? args[0].ToLowerInvariant() : "";

            if (mode == "--service")
            {
                ServiceBase.Run(new GuardService());
                return 0;
            }

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            if (mode == "--install")
            {
                string err = Installer.Install();
                if (args.Length < 2 || args[1] != "--quiet")
                    MessageBox.Show(err == null ? "DragonGuard service installed and started.\r\nThe tray agent starts automatically in every session." : "Install failed: " + err,
                        "DragonGuard", MessageBoxButtons.OK, err == null ? MessageBoxIcon.Information : MessageBoxIcon.Error);
                return err == null ? 0 : 1;
            }
            if (mode == "--uninstall")
            {
                string err = Installer.Uninstall();
                if (args.Length < 2 || args[1] != "--quiet")
                    MessageBox.Show(err == null ? "DragonGuard was uninstalled. Settings in " + Guard.DataDir + " were kept." : "Uninstall failed: " + err, "DragonGuard");
                return err == null ? 0 : 1;
            }

            if (mode != "--agent")
            {
                // Double-clicked: install / update the service if needed.
                bool installed = Installer.IsInstalled();
                bool fromInstallDir = string.Equals(Path.GetFullPath(Application.ExecutablePath), Path.GetFullPath(Installer.InstalledExe), StringComparison.OrdinalIgnoreCase);
                if (!installed || !fromInstallDir)
                {
                    string q = installed
                        ? "DragonGuard is already installed. Update it with this version?"
                        : "Install DragonGuard as a Windows service?\r\n\r\nIt will run all the time (from boot, also on the lock screen) and start the tray agent in every session.\r\n" +
                          "The program is copied to " + Installer.InstallDir + ".";
                    if (MessageBox.Show(q, "DragonGuard", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return 0;
                    string err = Installer.Install();
                    MessageBox.Show(err == null ? "DragonGuard service is installed and running.\r\nThe DragonGuard icon appears in the tray in a few seconds." : "Install failed: " + err,
                        "DragonGuard", MessageBoxButtons.OK, err == null ? MessageBoxIcon.Information : MessageBoxIcon.Error);
                    return 0;
                }
                if (!Installer.IsRunning())
                {
                    try { using (var sc = new ServiceController(Installer.ServiceName)) sc.Start(); } catch { }
                }
                // otherwise fall through and run as this session's agent (if none is running)
            }
            return RunAgent();
        }

        static int RunAgent()
        {
            bool created;
            using (var mutex = new Mutex(true, @"Local\UsbGuard_Agent", out created))
            {
                if (!created) return 0;
                Application.ThreadException += (s, e) => Guard.Log("UI error: " + e.Exception);
                AppDomain.CurrentDomain.UnhandledException += (s, e) => Guard.Log("Fatal: " + e.ExceptionObject);

                var app = new App();
                KeyHook.KeyBlocked += r => app.Post(() => app.OnKey(r));
                KeyHook.MouseBlocked += r => app.Post(() => app.OnMouse(r));
                try { KeyHook.Start(); }
                catch (Exception ex)
                {
                    MessageBox.Show("DragonGuard could not start the input hooks: " + ex.Message, "DragonGuard", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return 1;
                }

                // Get the allow/block lists from the service before judging any keyboard.
                app.Client.Start();
                var waitStart = DateTime.UtcNow;
                bool synced;
                while (!(synced = app.Synced.WaitOne(30)) && (DateTime.UtcNow - waitStart).TotalMilliseconds < 6000)
                    Application.DoEvents();
                if (!synced)
                {
                    Guard.LoadMirrorFromFile();
                    app.Balloon("DragonGuard", "The DragonGuard service is not running - only this session is protected.", ToolTipIcon.Warning);
                }

                try { DeviceWatcher.Start(app); }
                catch (Exception ex)
                {
                    MessageBox.Show("DragonGuard could not start: " + ex.Message, "DragonGuard", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return 1;
                }
                Application.Run(app);
                GC.KeepAlive(mutex);
            }
            return 0;
        }
    }
}
