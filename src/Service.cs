using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.ServiceProcess;
using System.Threading;
using System.Windows.Forms;

namespace UsbGuard
{
    internal class GuardService : ServiceBase
    {
        ServiceCore core;

        public GuardService()
        {
            ServiceName = Installer.ServiceName;
            CanStop = true;
            CanShutdown = true;
            CanHandleSessionChangeEvent = true;
        }

        protected override void OnStart(string[] args)
        {
            core = new ServiceCore();
            core.Start();
        }

        protected override void OnStop()
        {
            Guard.Log("DragonGuard service stopping");
        }

        protected override void OnSessionChange(SessionChangeDescription d)
        {
            if (core != null) core.OnSessionChange(d.Reason, (uint)d.SessionId);
        }
    }

    /// <summary>
    /// The always-on part (SYSTEM, from boot, also on the lock screen / before logon):
    /// watches HID / network / disk interfaces, switches off unknown keyboards, pointers and
    /// network adapters, re-disables blocked devices, owns the lists and talks to the agents.
    /// All state is touched only on the single worker thread.
    /// </summary>
    internal class ServiceCore
    {
        static readonly Guid GUID_DEVINTERFACE_KEYBOARD = new Guid("884b96c3-56ef-11d1-bc8c-00a0c91405dd");

        class Func
        {
            public IfaceKind Kind;
            public string Path, Inst;
            public bool Disabled;            // switched off by us, waiting for approval
            public PipeConn EnabledFor;      // keyboard temporarily on for arrow approval (agent holds the lock)
        }

        class Pending
        {
            public string Phys, Name, Note;
            public readonly List<Func> Funcs = new List<Func>();
        }

        readonly BlockingCollection<Action> queue = new BlockingCollection<Action>();
        readonly Dictionary<string, Pending> pending = new Dictionary<string, Pending>(StringComparer.OrdinalIgnoreCase);
        readonly HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        // Volumes of not-yet-trusted USB drives kept without a drive letter: \\?\Volume{guid}\ -> physical device.
        readonly Dictionary<string, string> lockedVolumes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        readonly List<Native.CM_NOTIFY_CALLBACK> callbacks = new List<Native.CM_NOTIFY_CALLBACK>(); // keep alive
        readonly PipeServer server = new PipeServer();
        readonly AgentLauncher launcher;
        System.Threading.Timer timer;

        public ServiceCore() { launcher = new AgentLauncher(server); }

        public void Start()
        {
            Guard.IsService = true;
            Guard.Load();
            Guard.Log("DragonGuard service started");
            if (Guard.FirstRun) Baseline(true);
            else if (Guard.LoadedVersion < 2) Baseline(false);

            var worker = new Thread(() =>
            {
                foreach (var a in queue.GetConsumingEnumerable())
                {
                    try { a(); } catch (Exception ex) { Guard.Log("Service error: " + ex); }
                }
            }) { IsBackground = true, Name = "GuardWorker" };
            worker.Start();

            Guard.LogAdded += line => server.Broadcast("LOG", line);
            server.Connected += c => queue.Add(() => OnAgentConnected(c));
            server.Disconnected += c => queue.Add(() => OnAgentDisconnected(c));
            server.Message += (c, m) => queue.Add(() => OnCommand(c, m));
            server.Start();

            Register(Native.GUID_DEVINTERFACE_HID, p => OnHid(p));
            Register(Native.GUID_DEVINTERFACE_NET, p => OnNet(p));
            Register(Native.GUID_DEVINTERFACE_DISK, p => OnDisk(p));
            Register(Native.GUID_DEVINTERFACE_VOLUME, p => OnVolume(p, 0));

            // Devices present at start (boot, service restart).
            queue.Add(() =>
            {
                foreach (string p in Dev.GetPresentInterfaces(Native.GUID_DEVINTERFACE_HID)) OnHid(p);
                foreach (string p in Dev.GetPresentInterfaces(Native.GUID_DEVINTERFACE_NET)) OnNet(p);
                foreach (string p in Dev.GetPresentInterfaces(Native.GUID_DEVINTERFACE_DISK)) OnDisk(p);
                foreach (string p in Dev.GetPresentInterfaces(Native.GUID_DEVINTERFACE_VOLUME)) OnVolume(p, 0);
                launcher.EnsureAllSessions();
            });

            timer = new System.Threading.Timer(_ => queue.Add(Tick), null, 2000, 2000);
        }

        void Register(Guid cls, Action<string> onArrival)
        {
            var f = new Native.CM_NOTIFY_FILTER
            {
                cbSize = Marshal.SizeOf(typeof(Native.CM_NOTIFY_FILTER)),
                FilterType = 0, // CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE
                ClassGuid = cls,
                Pad = new byte[384]
            };
            Native.CM_NOTIFY_CALLBACK cb = (h, ctx, action, data, size) =>
            {
                try
                {
                    string path = Marshal.PtrToStringUni(data + 24);
                    if (action == Native.CM_NOTIFY_ACTION_DEVICEINTERFACEARRIVAL) queue.Add(() => onArrival(path));
                    else if (action == Native.CM_NOTIFY_ACTION_DEVICEINTERFACEREMOVAL) queue.Add(() => { seen.Remove(path); CheckOnceAllowed(); });
                }
                catch { }
                return 0;
            };
            callbacks.Add(cb);
            IntPtr handle;
            int cr = Native.CM_Register_Notification(ref f, IntPtr.Zero, cb, out handle);
            if (cr != 0) Guard.Log("CM_Register_Notification failed for " + cls + ": CR=0x" + cr.ToString("X"));
        }

        public void OnSessionChange(SessionChangeReason reason, uint session)
        {
            if (reason == SessionChangeReason.SessionLogon || reason == SessionChangeReason.SessionUnlock ||
                reason == SessionChangeReason.ConsoleConnect || reason == SessionChangeReason.RemoteConnect)
                queue.Add(() => launcher.Ensure(session));
        }

        int tick;
        void Tick()
        {
            // Pending devices that were unplugged.
            foreach (var p in pending.Values.ToList())
                if (Dev.Locate(p.Phys) == 0)
                {
                    pending.Remove(p.Phys);
                    Guard.Log("Device unplugged before a decision: " + p.Name);
                    server.Broadcast("GONE", p.Phys);
                }
            CheckOnceAllowed();
            RecheckLockedVolumes();
            if (++tick % 5 == 0) launcher.EnsureAllSessions(); // restart crashed agents
        }

        void Later(int ms, Action a)
        {
            System.Threading.Tasks.Task.Delay(ms).ContinueWith(_ => { try { queue.Add(a); } catch { } });
        }

        // ------------------------------------------------------------------
        /// <summary>
        /// A volume appeared. If it belongs to a USB device that is not allowed (yet), remove its drive letter so it
        /// can't be opened until the user trusts it; the agent scans it through the volume name instead.
        /// </summary>
        void OnVolume(string path, int attempt)
        {
            string vol = Volumes.NameOf(path);
            string phys = vol == null ? null : Dev.PhysForVolume(vol);
            if (vol == null || phys == null)
            {
                // Right after arrival the volume may not be registered with the mount manager yet.
                if (attempt < 8 && Dev.GetPresentInterfaces(Native.GUID_DEVINTERFACE_VOLUME).Contains(path, StringComparer.OrdinalIgnoreCase))
                    Later(250, () => OnVolume(path, attempt + 1));
                return;
            }
            if (!phys.StartsWith(@"USB\", StringComparison.OrdinalIgnoreCase)) return;
            LockVolume(vol, phys);
            // The mount manager can hand out the letter a moment after the interface arrives: check again.
            if (attempt == 0) foreach (int ms in new[] { 300, 1000 }) Later(ms, () => LockVolume(vol, phys));
        }

        void LockVolume(string vol, string phys)
        {
            if (Guard.GetState(phys) == DevState.Allowed) return;
            if (Dev.Locate(phys) == 0) { lockedVolumes.Remove(vol); return; }
            string removed = Volumes.HideLetters(vol);
            bool isNew = !lockedVolumes.ContainsKey(vol);
            lockedVolumes[vol] = phys;
            if (removed.Length > 0)
                Guard.Log("Removed drive letter " + removed + " of untrusted USB drive until approval  [" + phys + "]");
            if (isNew) server.Broadcast("VOLUME", phys, vol);
        }

        void RecheckLockedVolumes()
        {
            foreach (var kv in lockedVolumes.ToList())
            {
                if (Dev.Locate(kv.Value) == 0 || Dev.PhysForVolume(kv.Key) == null) { lockedVolumes.Remove(kv.Key); continue; }
                LockVolume(kv.Key, kv.Value);
            }
        }

        /// <summary>The device was allowed: give its drives a letter back.</summary>
        void UnlockVolumes(string phys)
        {
            foreach (var kv in lockedVolumes.Where(x => string.Equals(x.Value, phys, StringComparison.OrdinalIgnoreCase)).ToList())
            {
                lockedVolumes.Remove(kv.Key);
                char? l = Volumes.GiveLetter(kv.Key);
                if (l != null) Guard.Log("Drive of allowed device is now available as " + l + ":  [" + phys + "]");
            }
        }

        /// <summary>"Allow once" lasts only while the device stays plugged in.</summary>
        void CheckOnceAllowed()
        {
            foreach (string id in Guard.OnceAllowed())
                if (Dev.Locate(id) == 0 && Guard.EndOnce(id))
                {
                    Guard.Log("One-time permission ended (device unplugged)  [" + id + "]");
                    SendState(id);
                }
        }

        // ------------------------------------------------------------------
        void OnHid(string path)
        {
            if (!seen.Add(path)) return;
            string inst = Dev.InstanceIdFromInterface(path);
            string what = Dev.ClassifyHid(inst);
            if (what == null) return;
            string phys; uint pi;
            if (!Dev.ResolvePhysical(inst, out phys, out pi) || !Dev.IsGuardedBus(phys)) return;
            Evaluate(phys, pi, what == "keyboard" ? IfaceKind.Keyboard : IfaceKind.Pointer, path, inst);
        }

        void OnNet(string path)
        {
            if (!seen.Add(path)) return;
            string inst = Dev.InstanceIdFromInterface(path);
            string phys; uint pi;
            if (!Dev.ResolvePhysical(inst, out phys, out pi) || !phys.StartsWith(@"USB\", StringComparison.OrdinalIgnoreCase)) return;
            Evaluate(phys, pi, IfaceKind.Network, path, inst);
        }

        void OnDisk(string path)
        {
            if (!seen.Add(path)) return;
            string inst = Dev.InstanceIdFromInterface(path);
            string phys; uint pi;
            if (!Dev.ResolvePhysical(inst, out phys, out pi) || !phys.StartsWith(@"USB\", StringComparison.OrdinalIgnoreCase)) return;
            Evaluate(phys, pi, IfaceKind.Storage, path, inst);
        }

        bool ConsoleAgentConnected()
        {
            return server.HasSession(Native.WTSGetActiveConsoleSessionId());
        }

        /// <summary>Is there a keyboard the user can already type with (built-in or allowed)?</summary>
        static bool TrustedKeyboardPresent()
        {
            foreach (string p in Dev.GetPresentInterfaces(GUID_DEVINTERFACE_KEYBOARD))
            {
                string phys; uint pi;
                string inst = Dev.InstanceIdFromInterface(p);
                if (!Dev.ResolvePhysical(inst, out phys, out pi)) continue;
                if (!Dev.IsGuardedBus(phys) || Guard.GetState(phys) == DevState.Allowed) return true;
            }
            return false;
        }

        void Evaluate(string phys, uint physInst, IfaceKind kind, string path, string inst)
        {
            DevState st = Guard.GetState(phys);
            if (st == DevState.Allowed) return;

            string name = Dev.GetName(physInst);
            string note = null;
            if (st == DevState.Blocked)
            {
                string err = Dev.DisableOrRemove(phys);
                if (err == null) { Guard.Log("Blocked device connected and disabled again: " + name + "  [" + phys + "]"); return; }
                note = "This device is on the block list but could not be disabled (" + err + "). Unplug it.";
                Guard.Log("Blocked device could not be disabled: " + name + " - " + err);
            }

            Pending p;
            if (!pending.TryGetValue(phys, out p))
            {
                p = new Pending { Phys = phys, Name = name };
                pending[phys] = p;
            }
            if (p.Funcs.Any(x => string.Equals(x.Path, path, StringComparison.OrdinalIgnoreCase))) return; // re-enabled for approval
            var f = new Func { Kind = kind, Path = path, Inst = inst };

            if (kind != IfaceKind.Storage)
            {
                bool leaveOn = kind == IfaceKind.Keyboard && !ConsoleAgentConnected() && !TrustedKeyboardPresent();
                if (leaveOn)
                {
                    note = Join(note, "No other keyboard was available, so this keyboard was left on to let you log in. Approve it now with the arrow keys.");
                    Guard.Log("New keyboard left on (no trusted keyboard, nobody logged in): " + name + "  [" + inst + "]");
                }
                else
                {
                    string err = Dev.DisableInstance(inst);
                    if (err == null)
                    {
                        f.Disabled = true;
                        Guard.Log("Switched off new " + KindText(kind) + " until approval: " + name + "  [" + inst + "]");
                    }
                    else if (kind == IfaceKind.Keyboard && err == Dev.NotDisableableText)
                    {
                        // Normal for many HID keyboards: the agent's input lock blocks its keys instead.
                        note = Join(note, "Windows does not allow this keyboard to be switched off, so all keyboard input is locked until you decide.");
                        Guard.Log("Keyboard can't be switched off (not disableable), relying on the input lock: " + name + "  [" + inst + "]");
                    }
                    else
                    {
                        note = Join(note, "Could not switch off the new " + KindText(kind) + ": " + err);
                        Guard.Log("Could not disable " + kind + " " + inst + ": " + err);
                    }
                }
            }
            if (note != null) p.Note = note;
            p.Funcs.Add(f);
            Guard.Log("NEW DEVICE [" + kind.ToString().ToLowerInvariant() + "] " + name + "  [" + phys + "] - waiting for approval");
            server.Broadcast(PendingMsg(p, f));
        }

        static string Join(string a, string b) { return a == null ? b : a + "\r\n" + b; }

        static string KindText(IfaceKind k)
        {
            switch (k)
            {
                case IfaceKind.Keyboard: return "keyboard";
                case IfaceKind.Pointer: return "mouse/pointer";
                case IfaceKind.Network: return "network adapter";
                default: return "storage";
            }
        }

        static string[] PendingMsg(Pending p, Func f)
        {
            return new[] { "PENDING", p.Phys, f.Kind.ToString(), f.Path, p.Name, f.Disabled ? "1" : "0", f.Inst, p.Note ?? "",
                (f.Kind == IfaceKind.Pointer && !f.Disabled) ? "1" : "0" }; // 1 = agent must freeze the mouse
        }

        // ------------------------------------------------------------------
        void OnAgentConnected(PipeConn c)
        {
            Guard.Log("Tray agent connected (session " + c.Session + ")");
        }

        void OnAgentDisconnected(PipeConn c)
        {
            // A keyboard that was on for arrow approval must not stay on without the agent's lock.
            foreach (var p in pending.Values)
                foreach (var f in p.Funcs.Where(x => x.EnabledFor == c))
                {
                    f.EnabledFor = null;
                    if (Dev.DisableInstance(f.Inst) == null) f.Disabled = true;
                }
            Guard.Log("Tray agent disconnected (session " + c.Session + ")");
        }

        void SendState(string id)
        {
            server.Broadcast("STATE", id, Guard.NameOf(id), Guard.StateChar(id).ToString());
        }

        void OnCommand(PipeConn c, string[] m)
        {
            if (m.Length == 0) return;
            string cmd = m[0];
            string phys = m.Length > 1 ? m[1] : null;
            Pending p = null;
            if (phys != null) pending.TryGetValue(phys, out p);

            switch (cmd)
            {
                case "HELLO":
                    foreach (var e in Guard.Snapshot())
                        c.Send("STATE", e.Id, e.Name, Guard.StateChar(e.Id).ToString());
                    foreach (var pp in pending.Values)
                        foreach (var f in pp.Funcs) c.Send(PendingMsg(pp, f));
                    foreach (var kv in lockedVolumes) c.Send("VOLUME", kv.Value, kv.Key);
                    c.Send("SYNCED");
                    break;

                case "LOG":
                    if (phys != null) Guard.Log("[session " + c.Session + "] " + phys);
                    break;

                case "ENABLE_KB":
                    // Only the agent on the physical console may switch a pending keyboard on (it locks input first).
                    if (p == null || c.Session != Native.WTSGetActiveConsoleSessionId()) break;
                    foreach (var f in p.Funcs.Where(x => x.Kind == IfaceKind.Keyboard && x.Disabled))
                    {
                        string err = Dev.EnableInstance(f.Inst);
                        if (err == null) { f.Disabled = false; f.EnabledFor = c; }
                        else Guard.Log("Could not switch keyboard on for approval: " + err);
                    }
                    break;

                case "DISABLE_KB":
                    if (p == null) break;
                    foreach (var f in p.Funcs.Where(x => x.EnabledFor != null))
                    {
                        f.EnabledFor = null;
                        if (Dev.DisableInstance(f.Inst) == null) f.Disabled = true;
                    }
                    break;

                case "ALLOW":
                {
                    // m[3]: "1" remember, "0" until restart, "O" once (until unplugged)
                    string name = m.Length > 2 ? m[2] : (p != null ? p.Name : "");
                    string mode = m.Length > 3 ? m[3] : "0";
                    if (mode == "O") Guard.AllowOnce(phys); else Guard.Allow(phys, name, mode == "1");
                    Guard.Log("ALLOWED " + (mode == "1" ? "" : mode == "O" ? "(once, until unplugged) " : "(until restart) ") + name + "  [" + phys + "]");
                    if (p != null)
                    {
                        pending.Remove(phys);
                        foreach (var f in p.Funcs.Where(x => x.Disabled))
                        {
                            string err = Dev.EnableInstance(f.Inst);
                            if (err != null) Guard.Log("  could not re-enable " + f.Inst + ": " + err);
                        }
                    }
                    SendState(phys);
                    UnlockVolumes(phys); // after STATE, so the agents scan the drive as an allowed one
                    server.Broadcast("DECIDED", phys, "A", "");
                    break;
                }

                case "BLOCK":
                {
                    string name = m.Length > 2 ? m[2] : (p != null ? p.Name : "");
                    bool remember = m.Length > 3 && m[3] == "1";
                    if (remember) Guard.Block(phys, name);
                    string err = Dev.DisableOrRemove(phys);
                    if (err == null)
                    {
                        pending.Remove(phys);
                        Guard.Log("BLOCKED and disabled " + name + "  [" + phys + "]");
                    }
                    else Guard.Log("BLOCK of " + name + " failed to disable: " + err);
                    SendState(phys);
                    server.Broadcast("DECIDED", phys, "B", err ?? "");
                    break;
                }

                case "SETSTATE": // from the device list: SETSTATE id name A|B
                {
                    if (m.Length < 4) break;
                    if (m[3] == "B") { Guard.Block(phys, m[2]); string e = Dev.DisableOrRemove(phys); Guard.Log("Blocked from device list: " + m[2] + (e == null ? "" : " (" + e + ")")); }
                    else { Guard.Allow(phys, m[2], true); string e = Dev.Enable(phys); Guard.Log("Allowed from device list: " + m[2] + (e == null ? "" : " (" + e + ")")); }
                    SendState(phys);
                    if (m[3] != "B") UnlockVolumes(phys);
                    break;
                }

                case "FORGET":
                {
                    bool wasBlocked = Guard.GetState(phys) == DevState.Blocked;
                    Guard.Forget(phys);
                    if (wasBlocked) Dev.Enable(phys);
                    Guard.Log("Forgot device [" + phys + "]");
                    SendState(phys);
                    break;
                }
            }
        }

        // ------------------------------------------------------------------
        /// <summary>First run: trust what is connected now.</summary>
        static void Baseline(bool all)
        {
            var seenPhys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            Action<string, bool> trust = (inst, usbOnly) =>
            {
                string phys; uint pi;
                if (!Dev.ResolvePhysical(inst, out phys, out pi) || !Dev.IsGuardedBus(phys)) return;
                if (usbOnly && !phys.StartsWith(@"USB\", StringComparison.OrdinalIgnoreCase)) return;
                if (!seenPhys.Add(phys)) return;
                string name = Dev.GetName(pi);
                Guard.Allow(phys, name, true);
                Guard.Log("Baseline: trusted already-connected device " + name + "  [" + phys + "]");
            };
            foreach (string p in Dev.GetPresentInterfaces(Native.GUID_DEVINTERFACE_HID))
            {
                string inst = Dev.InstanceIdFromInterface(p);
                string what = Dev.ClassifyHid(inst);
                if (what == null || (!all && what == "keyboard")) continue;
                trust(inst, false);
            }
            foreach (string p in Dev.GetPresentInterfaces(Native.GUID_DEVINTERFACE_NET)) trust(Dev.InstanceIdFromInterface(p), true);
            if (all)
                foreach (string p in Dev.GetPresentInterfaces(Native.GUID_DEVINTERFACE_DISK)) trust(Dev.InstanceIdFromInterface(p), true);
            Guard.Save();
        }
    }

    // =====================================================================
    /// <summary>Starts the tray agent in each logged-on session, elevated, without a UAC prompt.</summary>
    internal class AgentLauncher
    {
        readonly PipeServer server;
        readonly Dictionary<uint, Process> agents = new Dictionary<uint, Process>();
        readonly Dictionary<uint, List<DateTime>> starts = new Dictionary<uint, List<DateTime>>();

        public AgentLauncher(PipeServer s) { server = s; }

        public void EnsureAllSessions()
        {
            IntPtr info; int count;
            if (!Native.WTSEnumerateSessions(IntPtr.Zero, 0, 1, out info, out count)) return;
            try
            {
                int size = Marshal.SizeOf(typeof(Native.WTS_SESSION_INFO));
                for (int i = 0; i < count; i++)
                {
                    var s = (Native.WTS_SESSION_INFO)Marshal.PtrToStructure(info + i * size, typeof(Native.WTS_SESSION_INFO));
                    if (s.State == 0 && s.SessionId != 0) Ensure(s.SessionId);
                }
            }
            finally { Native.WTSFreeMemory(info); }
        }

        public void Ensure(uint session)
        {
            if (session == 0 || server.HasSession(session)) return;
            Process p;
            if (agents.TryGetValue(session, out p))
            {
                try { if (!p.HasExited) return; } catch { }
                agents.Remove(session);
            }
            // Crash-loop protection: max 5 starts per 2 minutes per session.
            List<DateTime> l;
            if (!starts.TryGetValue(session, out l)) starts[session] = l = new List<DateTime>();
            l.RemoveAll(t => (DateTime.Now - t).TotalMinutes > 2);
            if (l.Count >= 5) return;
            l.Add(DateTime.Now);
            Launch(session);
        }

        static int GetInt(IntPtr token, int cls)
        {
            IntPtr buf = Marshal.AllocHGlobal(16);
            try { int ret; return Native.GetTokenInformation(token, cls, buf, 16, out ret) ? Marshal.ReadInt32(buf) : -1; }
            finally { Marshal.FreeHGlobal(buf); }
        }

        void Launch(uint session)
        {
            IntPtr user;
            if (!Native.WTSQueryUserToken(session, out user)) return; // nobody logged on in that session
            IntPtr tok = IntPtr.Zero, env = IntPtr.Zero;
            try
            {
                string mode;
                int elevationType = GetInt(user, Native.TokenElevationType); // 1 default, 2 full, 3 limited
                bool isAdmin;
                using (var id = new WindowsIdentity(user)) isAdmin = new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);

                if (elevationType == 3)
                {
                    // Admin with UAC: use the linked (elevated) token.
                    IntPtr buf = Marshal.AllocHGlobal(IntPtr.Size);
                    int ret;
                    if (!Native.GetTokenInformation(user, Native.TokenLinkedToken, buf, IntPtr.Size, out ret)) { Marshal.FreeHGlobal(buf); throw new Exception("no linked token"); }
                    IntPtr linked = Marshal.ReadIntPtr(buf);
                    Marshal.FreeHGlobal(buf);
                    Native.DuplicateTokenEx(linked, Native.TOKEN_ALL_ACCESS, IntPtr.Zero, 2, 1, out tok);
                    Native.CloseHandle(linked);
                    mode = "elevated user";
                }
                else if (isAdmin)
                {
                    Native.DuplicateTokenEx(user, Native.TOKEN_ALL_ACCESS, IntPtr.Zero, 2, 1, out tok);
                    mode = "admin user";
                }
                else
                {
                    // Standard user: run the agent as SYSTEM inside the user's session (high integrity is
                    // needed so the hooks also see input to elevated windows). Admin functions are hidden.
                    IntPtr sys;
                    Native.OpenProcessToken(Native.GetCurrentProcess(), Native.TOKEN_ALL_ACCESS, out sys);
                    Native.DuplicateTokenEx(sys, Native.TOKEN_ALL_ACCESS, IntPtr.Zero, 2, 1, out tok);
                    Native.CloseHandle(sys);
                    uint s = session;
                    Native.SetTokenInformation(tok, Native.TokenSessionId, ref s, 4);
                    mode = "SYSTEM (standard user session)";
                }
                if (tok == IntPtr.Zero) throw new Exception("token duplication failed");

                Native.CreateEnvironmentBlock(out env, user, false);
                string exe = Installer.InstalledExe;
                var si = new Native.STARTUPINFO { cb = Marshal.SizeOf(typeof(Native.STARTUPINFO)), lpDesktop = @"winsta0\default" };
                Native.PROCESS_INFORMATION pi;
                if (!Native.CreateProcessAsUser(tok, exe, "\"" + exe + "\" --agent", IntPtr.Zero, IntPtr.Zero, false,
                        0x400 /*CREATE_UNICODE_ENVIRONMENT*/, env, Path.GetDirectoryName(exe), ref si, out pi))
                    throw new Exception("CreateProcessAsUser failed: " + Marshal.GetLastWin32Error());
                Native.CloseHandle(pi.hThread);
                Native.CloseHandle(pi.hProcess);
                try { agents[session] = Process.GetProcessById(pi.dwProcessId); } catch { }
                Guard.Log("Started tray agent in session " + session + " as " + mode);
            }
            catch (Exception ex) { Guard.Log("Could not start tray agent in session " + session + ": " + ex.Message); }
            finally
            {
                if (env != IntPtr.Zero) Native.DestroyEnvironmentBlock(env);
                if (tok != IntPtr.Zero) Native.CloseHandle(tok);
                Native.CloseHandle(user);
            }
        }
    }

    // =====================================================================
    internal static class Installer
    {
        public const string ServiceName = "UsbGuard";

        public static string InstallDir
        {
            get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "UsbGuard"); }
        }

        public static string InstalledExe { get { return Path.Combine(InstallDir, "UsbGuard.exe"); } }

        public static bool IsInstalled()
        {
            return ServiceController.GetServices().Any(s => s.ServiceName.Equals(ServiceName, StringComparison.OrdinalIgnoreCase));
        }

        public static bool IsRunning()
        {
            try { using (var sc = new ServiceController(ServiceName)) return sc.Status == ServiceControllerStatus.Running; }
            catch { return false; }
        }

        static int Run(string exe, string args)
        {
            var psi = new ProcessStartInfo(exe, args) { CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
            using (var p = Process.Start(psi)) { p.StandardOutput.ReadToEnd(); p.StandardError.ReadToEnd(); p.WaitForExit(); return p.ExitCode; }
        }

        static void StopService()
        {
            try
            {
                using (var sc = new ServiceController(ServiceName))
                    if (sc.Status != ServiceControllerStatus.Stopped)
                    {
                        sc.Stop();
                        sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(20));
                    }
            }
            catch { }
        }

        static void KillOtherInstances()
        {
            int me = Process.GetCurrentProcess().Id;
            foreach (var p in Process.GetProcessesByName("UsbGuard"))
                if (p.Id != me) try { p.Kill(); p.WaitForExit(3000); } catch { }
        }

        /// <summary>Installs or updates the service (copies the exe to Program Files, admin-only location).</summary>
        public static string Install()
        {
            try
            {
                bool exists = IsInstalled();
                if (exists) StopService();
                KillOtherInstances();

                Directory.CreateDirectory(InstallDir);
                string self = Path.GetFullPath(Application.ExecutablePath);
                if (!string.Equals(self, Path.GetFullPath(InstalledExe), StringComparison.OrdinalIgnoreCase))
                    File.Copy(self, InstalledExe, true);

                if (!exists)
                {
                    int rc = Run("sc.exe", "create " + ServiceName + " binPath= \"\\\"" + InstalledExe + "\\\" --service\" start= auto DisplayName= \"" + Branding.Name + "\"");
                    if (rc != 0) return "sc create failed (" + rc + ")";
                }
                Run("sc.exe", "config " + ServiceName + " DisplayName= \"" + Branding.Name + "\""); // also renames older installs
                Run("sc.exe", "description " + ServiceName + " \"Protects against BadUSB keyboards, mice, rogue network adapters and malicious USB drives.\"");
                Run("sc.exe", "failure " + ServiceName + " reset= 86400 actions= restart/2000/restart/5000/restart/10000");
                Run("schtasks.exe", "/Delete /TN UsbGuard /F"); // autostart task of the old tray-only version

                using (var sc = new ServiceController(ServiceName))
                {
                    sc.Start();
                    sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(20));
                }
                return null;
            }
            catch (Exception ex) { return ex.Message; }
        }

        public static string Uninstall()
        {
            try
            {
                StopService();
                Run("sc.exe", "delete " + ServiceName);
                KillOtherInstances();
                // Remove the program folder after this process has exited (settings in ProgramData are kept).
                Process.Start(new ProcessStartInfo("cmd.exe", "/c ping 127.0.0.1 -n 3 >nul & rmdir /s /q \"" + InstallDir + "\"")
                    { CreateNoWindow = true, UseShellExecute = false });
                return null;
            }
            catch (Exception ex) { return ex.Message; }
        }
    }
}
