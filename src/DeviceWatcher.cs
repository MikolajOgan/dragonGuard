using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows.Forms;

namespace UsbGuard
{
    internal enum IfaceKind { Keyboard, Storage, Network, Pointer }

    internal class DeviceEvent
    {
        public string Phys, Name, Path, Note;
        public IfaceKind Kind;
        public bool IsTest;
        public string DisabledInst;  // function the service switched off until approval
        public bool MouseHeld;       // pointer could not be switched off -> all mouse input frozen instead
    }

    internal interface IDeviceSink
    {
        void InterfaceArrived(DeviceEvent e);
        void VolumeArrived(char letter, string phys);
    }

    /// <summary>
    /// Agent-side watcher (hidden window in the user's session). The service does the device control;
    /// this part only gives the instant keyboard lock (raw-input arrival, faster than any round trip)
    /// and reports new drive letters for the autorun scan.
    /// </summary>
    internal class DeviceWatcher : NativeWindow
    {
        class Iface { public string Path, Phys; }

        readonly IDeviceSink sink;
        readonly Dictionary<IntPtr, Iface> keyboards = new Dictionary<IntPtr, Iface>();
        IntPtr rawHeader;

        DeviceWatcher(IDeviceSink sink) { this.sink = sink; }

        public static void Start(IDeviceSink sink)
        {
            var ready = new ManualResetEvent(false);
            Exception err = null;
            var t = new Thread(() =>
            {
                try { new DeviceWatcher(sink).Init(); }
                catch (Exception ex) { err = ex; }
                ready.Set();
                if (err == null) Application.Run();
            });
            t.Name = "DeviceWatcher";
            t.IsBackground = true;
            t.Priority = ThreadPriority.AboveNormal;
            t.SetApartmentState(ApartmentState.STA);
            t.Start();
            ready.WaitOne();
            if (err != null) throw err;
        }

        void Init()
        {
            CreateHandle(new CreateParams { Caption = "UsbGuardWatcher" });
            rawHeader = Marshal.AllocHGlobal(64);

            var rid = new[] { new Native.RAWINPUTDEVICE {
                usUsagePage = 0x01, usUsage = 0x06,
                dwFlags = Native.RIDEV_INPUTSINK | Native.RIDEV_DEVNOTIFY, hwndTarget = Handle } };
            if (!Native.RegisterRawInputDevices(rid, 1, (uint)Marshal.SizeOf(typeof(Native.RAWINPUTDEVICE))))
                throw new InvalidOperationException("RegisterRawInputDevices failed: " + Marshal.GetLastWin32Error());

            foreach (IntPtr h in Dev.RawKeyboards()) OnKeyboardArrival(h);
            foreach (DriveInfo d in DriveInfo.GetDrives())
                if (d.DriveType == DriveType.Removable || d.DriveType == DriveType.Fixed)
                    OnVolumeArrival(d.Name[0], true);
        }

        protected override void WndProc(ref Message m)
        {
            try
            {
                switch (m.Msg)
                {
                    case Native.WM_INPUT_DEVICE_CHANGE:
                        if (m.WParam.ToInt32() == Native.GIDC_ARRIVAL) OnKeyboardArrival(m.LParam);
                        else keyboards.Remove(m.LParam);
                        break;
                    case Native.WM_INPUT:
                        OnRawInput(m.LParam);
                        break;
                    case Native.WM_DEVICECHANGE:
                        OnDeviceChange(m.WParam.ToInt32(), m.LParam);
                        break;
                }
            }
            catch (Exception ex) { Guard.Log("Watcher error: " + ex.Message); }
            base.WndProc(ref m);
        }

        void OnKeyboardArrival(IntPtr h)
        {
            if (h == IntPtr.Zero || keyboards.ContainsKey(h)) return;
            // Lock the keyboard while we evaluate: a BadUSB starts typing as soon as it is enumerated.
            string evalKey = "eval:" + h.ToInt64();
            Guard.Hold(evalKey);
            try
            {
                if (Dev.RawDeviceType(h) != Native.RIM_TYPEKEYBOARD) { keyboards[h] = null; return; }
                string path = Dev.RawDeviceName(h);
                if (path == null) { keyboards[h] = null; return; }
                string inst = Dev.InstanceIdFromInterface(path);
                string phys; uint physInst;
                if (!Dev.ResolvePhysical(inst, out phys, out physInst)) phys = inst;
                keyboards[h] = new Iface { Path = path, Phys = phys };
                if (!Dev.IsGuardedBus(phys)) return;

                DevState st = Guard.GetState(phys);
                if (st == DevState.Allowed) return;
                if (st == DevState.Blocked)
                {
                    // The service switches it off; keep the keyboard locked meanwhile.
                    string key = "block:" + phys;
                    Guard.Hold(key);
                    ThreadPool.QueueUserWorkItem(_ => { Thread.Sleep(5000); Guard.Release(key); });
                    return;
                }
                Guard.Hold(phys); // stays locked until the user decides
                sink.InterfaceArrived(new DeviceEvent { Phys = phys, Name = Dev.GetName(physInst), Kind = IfaceKind.Keyboard, Path = path });
            }
            finally { Guard.Release(evalKey); }
        }

        /// <summary>Fallback: a keystroke from a keyboard we have never evaluated.</summary>
        void OnRawInput(IntPtr hRaw)
        {
            uint hdr = (uint)(IntPtr.Size == 8 ? 24 : 16), size = hdr;
            if ((int)Native.GetRawInputData(hRaw, Native.RID_HEADER, rawHeader, ref size, hdr) <= 0) return;
            IntPtr dev = Marshal.ReadIntPtr(rawHeader, 8);
            if (dev != IntPtr.Zero && !keyboards.ContainsKey(dev))
            {
                Guard.Log("Keystroke from a not yet evaluated keyboard - evaluating now.");
                OnKeyboardArrival(dev);
            }
        }

        void OnDeviceChange(int evt, IntPtr lParam)
        {
            if (lParam == IntPtr.Zero || evt != Native.DBT_DEVICEARRIVAL) return;
            if (Marshal.ReadInt32(lParam, 4) != Native.DBT_DEVTYP_VOLUME) return;
            int mask = Marshal.ReadInt32(lParam, 12);
            for (int i = 0; i < 26; i++)
                if ((mask & (1 << i)) != 0) OnVolumeArrival((char)('A' + i), false);
        }

        void OnVolumeArrival(char letter, bool startup)
        {
            string phys = Dev.PhysForDrive(letter);
            if (startup && phys == null) return; // only USB volumes on startup
            sink.VolumeArrived(letter, phys);
        }
    }
}
