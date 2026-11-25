using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;

namespace UsbGuard
{
    /// <summary>Line protocol: tab-separated fields, escaped so names/notes/log lines can contain tabs and newlines.</summary>
    internal static class Proto
    {
        public const string PipeName = "UsbGuard";

        public static string Encode(params string[] fields)
        {
            var sb = new StringBuilder();
            for (int i = 0; i < fields.Length; i++)
            {
                if (i > 0) sb.Append('\t');
                foreach (char c in fields[i] ?? "")
                {
                    switch (c)
                    {
                        case '\\': sb.Append("\\\\"); break;
                        case '\t': sb.Append("\\t"); break;
                        case '\n': sb.Append("\\n"); break;
                        case '\r': sb.Append("\\r"); break;
                        default: sb.Append(c); break;
                    }
                }
            }
            return sb.ToString();
        }

        public static string[] Decode(string line)
        {
            var list = new List<string>();
            var sb = new StringBuilder();
            for (int i = 0; i < line.Length; i++)
            {
                char c = line[i];
                if (c == '\t') { list.Add(sb.ToString()); sb.Length = 0; }
                else if (c == '\\' && i + 1 < line.Length)
                {
                    char n = line[++i];
                    sb.Append(n == 't' ? '\t' : n == 'n' ? '\n' : n == 'r' ? '\r' : n);
                }
                else sb.Append(c);
            }
            list.Add(sb.ToString());
            return list.ToArray();
        }
    }

    // =====================================================================
    /// <summary>
    /// Outgoing lines go through a queue and a dedicated writer thread, so the caller (UI thread / service worker)
    /// never waits on pipe I/O, even if the other side is hung.
    /// </summary>
    internal sealed class LineSender
    {
        const int MaxQueued = 5000;
        readonly BlockingCollection<string> queue = new BlockingCollection<string>();
        readonly Action onFail;
        volatile bool dead;

        public LineSender(Stream s, Action onFail)
        {
            this.onFail = onFail;
            var w = new StreamWriter(s, new UTF8Encoding(false)) { AutoFlush = true };
            new Thread(() =>
            {
                try { foreach (string line in queue.GetConsumingEnumerable()) w.WriteLine(line); }
                catch { Fail(); }
            }) { IsBackground = true, Name = "PipeWriter" }.Start();
        }

        public bool Send(string line)
        {
            if (dead) return false;
            if (queue.Count > MaxQueued) { Fail(); return false; } // other side stopped reading
            try { queue.Add(line); return true; }
            catch { return false; }
        }

        public void Stop()
        {
            dead = true;
            try { queue.CompleteAdding(); } catch { }
        }

        void Fail()
        {
            if (dead) return;
            Stop();
            if (onFail != null) try { onFail(); } catch { }
        }
    }

    // =====================================================================
    internal class PipeConn
    {
        public readonly NamedPipeServerStream Stream;
        public uint Session;
        readonly LineSender sender;
        public volatile bool Closed;

        public PipeConn(NamedPipeServerStream s)
        {
            Stream = s;
            sender = new LineSender(s, () => { Closed = true; try { Stream.Dispose(); } catch { } });
        }

        public bool Send(params string[] fields)
        {
            if (Closed) return false;
            return sender.Send(Proto.Encode(fields));
        }

        public void Stop() { sender.Stop(); }
    }

    // =====================================================================
    /// <summary>Service side. Only SYSTEM and (elevated) Administrators can connect.</summary>
    internal class PipeServer
    {
        readonly List<PipeConn> conns = new List<PipeConn>();
        public event Action<PipeConn> Connected, Disconnected;
        public event Action<PipeConn, string[]> Message;

        public void Start()
        {
            var t = new Thread(AcceptLoop) { IsBackground = true, Name = "PipeAccept" };
            t.Start();
        }

        static PipeSecurity Security()
        {
            var ps = new PipeSecurity();
            ps.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                PipeAccessRights.FullControl, AccessControlType.Allow));
            ps.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                PipeAccessRights.ReadWrite | PipeAccessRights.Synchronize, AccessControlType.Allow));
            return ps;
        }

        void AcceptLoop()
        {
            while (true)
            {
                NamedPipeServerStream s = null;
                try
                {
                    s = new NamedPipeServerStream(Proto.PipeName, PipeDirection.InOut, 32, PipeTransmissionMode.Byte,
                        PipeOptions.Asynchronous, 8192, 8192, Security());
                    s.WaitForConnection();
                    var c = new PipeConn(s);
                    uint sid;
                    if (Native.GetNamedPipeClientSessionId(s.SafePipeHandle.DangerousGetHandle(), out sid)) c.Session = sid;
                    lock (conns) conns.Add(c);
                    var t = new Thread(() => ReadLoop(c)) { IsBackground = true, Name = "PipeConn" };
                    t.Start();
                }
                catch (Exception ex)
                {
                    Guard.Log("Pipe server error: " + ex.Message);
                    if (s != null) try { s.Dispose(); } catch { }
                    Thread.Sleep(1000);
                }
            }
        }

        void ReadLoop(PipeConn c)
        {
            var h = Connected; if (h != null) h(c);
            try
            {
                using (var r = new StreamReader(c.Stream, Encoding.UTF8))
                {
                    string line;
                    while ((line = r.ReadLine()) != null)
                    {
                        var m = Message;
                        if (m != null) m(c, Proto.Decode(line));
                    }
                }
            }
            catch { }
            c.Closed = true;
            c.Stop();
            lock (conns) conns.Remove(c);
            try { c.Stream.Dispose(); } catch { }
            var d = Disconnected; if (d != null) d(c);
        }

        public void Broadcast(params string[] fields)
        {
            PipeConn[] all;
            lock (conns) all = conns.ToArray();
            foreach (var c in all) c.Send(fields);
        }

        public bool HasSession(uint session)
        {
            lock (conns) return conns.Exists(c => !c.Closed && c.Session == session);
        }
    }

    // =====================================================================
    /// <summary>Agent side. Reconnects automatically and verifies the server is the installed UsbGuard service.</summary>
    internal class PipeClient
    {
        volatile LineSender sender;
        public volatile bool IsConnected;
        public event Action Connected, Disconnected;
        public event Action<string[]> Message; // raised on the reader thread

        public void Start()
        {
            var t = new Thread(Loop) { IsBackground = true, Name = "PipeClient" };
            t.Start();
        }

        void Loop()
        {
            bool warned = false;
            while (true)
            {
                try
                {
                    using (var c = new NamedPipeClientStream(".", Proto.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous))
                    {
                        c.Connect(2000);
                        string why = VerifyServer(c);
                        if (why != null)
                        {
                            if (!warned) { warned = true; Guard.AddRemoteLine("Refusing pipe server: " + why); }
                            Thread.Sleep(5000);
                            continue;
                        }
                        var pipe = c;
                        sender = new LineSender(c, () => { try { pipe.Dispose(); } catch { } }); // unblocks the reader
                        IsConnected = true;
                        warned = false;
                        var h = Connected; if (h != null) h();
                        using (var r = new StreamReader(c, Encoding.UTF8))
                        {
                            string line;
                            while ((line = r.ReadLine()) != null)
                            {
                                var m = Message;
                                if (m != null) { try { m(Proto.Decode(line)); } catch { } }
                            }
                        }
                    }
                }
                catch { }
                var old = sender;
                sender = null;
                if (old != null) old.Stop();
                if (IsConnected)
                {
                    IsConnected = false;
                    var d = Disconnected; if (d != null) d();
                }
                Thread.Sleep(2000);
            }
        }

        /// <summary>Pipe squatting protection: the server process must be our own executable.</summary>
        static string VerifyServer(NamedPipeClientStream c)
        {
            uint pid;
            if (!Native.GetNamedPipeServerProcessId(c.SafePipeHandle.DangerousGetHandle(), out pid)) return "cannot get server pid";
            IntPtr hp = Native.OpenProcess(0x1000 /*PROCESS_QUERY_LIMITED_INFORMATION*/, false, pid);
            if (hp == IntPtr.Zero) return "cannot open server process";
            try
            {
                var sb = new StringBuilder(1024);
                int size = sb.Capacity;
                if (!Native.QueryFullProcessImageName(hp, 0, sb, ref size)) return "cannot read server image";
                string server = Path.GetFullPath(sb.ToString());
                string expected = Path.GetFullPath(Installer.InstalledExe);
                return string.Equals(server, expected, StringComparison.OrdinalIgnoreCase) ? null : "unexpected server " + server;
            }
            finally { Native.CloseHandle(hp); }
        }

        public bool Send(params string[] fields)
        {
            var snd = sender;
            if (!IsConnected || snd == null) return false;
            return snd.Send(Proto.Encode(fields));
        }
    }
}
