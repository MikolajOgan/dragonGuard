using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace UsbGuard
{
    /// <summary>PnP helpers: map interfaces to the physical device, names, enable/disable.</summary>
    internal static class Dev
    {
        static readonly Native.DEVPROPKEY InstanceIdKey =
            new Native.DEVPROPKEY(new Guid("78c34fc8-104a-4aca-9ea4-524d52996e57"), 256);
        static readonly Native.DEVPROPKEY BusReportedDescKey =
            new Native.DEVPROPKEY(new Guid("540b947e-8b40-45bc-a8a2-6a0b894cbda2"), 4);

        const uint CM_DRP_DEVICEDESC = 0x01, CM_DRP_SERVICE = 0x05, CM_DRP_MFG = 0x0C, CM_DRP_FRIENDLYNAME = 0x0D;
        const uint CM_DISABLE_ABSOLUTE = 0x1, CM_DISABLE_UI_NOT_OK = 0x4;

        public static string InstanceIdFromInterface(string path)
        {
            try
            {
                Native.DEVPROPKEY k = InstanceIdKey;
                uint type, size = 0;
                Native.CM_Get_Device_Interface_PropertyW(path, ref k, out type, null, ref size, 0);
                if (size > 0)
                {
                    byte[] b = new byte[size];
                    if (Native.CM_Get_Device_Interface_PropertyW(path, ref k, out type, b, ref size, 0) == 0)
                        return Encoding.Unicode.GetString(b).TrimEnd('\0');
                }
            }
            catch { }
            // Fallback: \\?\HID#VID_x&PID_y#7&abc&0&0000#{guid}  ->  HID\VID_x&PID_y\7&abc&0&0000
            string s = path;
            if (s.StartsWith(@"\\?\")) s = s.Substring(4);
            int i = s.LastIndexOf("#{", StringComparison.Ordinal);
            if (i > 0) s = s.Substring(0, i);
            return s.Replace('#', '\\');
        }

        public static uint Locate(string id)
        {
            uint d;
            return Native.CM_Locate_DevNodeW(out d, id, 0) == 0 ? d : 0;
        }

        public static string GetId(uint dev)
        {
            StringBuilder sb = new StringBuilder(512);
            return Native.CM_Get_Device_IDW(dev, sb, sb.Capacity, 0) == 0 ? sb.ToString() : null;
        }

        /// <summary>
        /// Walks up from a HID collection / storage disk to the physical device node
        /// (e.g. HID\VID..&amp;MI_00\.. -> USB\VID..&amp;MI_00\.. -> USB\VID_1234&amp;PID_5678\SERIAL).
        /// All interfaces of one composite gadget (keyboard + storage) end up on the same node.
        /// </summary>
        public static bool ResolvePhysical(string instanceId, out string physId, out uint physInst)
        {
            physId = null; physInst = 0;
            uint d = Locate(instanceId);
            if (d == 0) return false;
            string id = GetId(d);
            for (int i = 0; i < 8 && id != null; i++)
            {
                string u = id.ToUpperInvariant();
                bool ascend = u.StartsWith(@"HID\") || u.StartsWith(@"USBSTOR\") || u.StartsWith(@"SCSI\") ||
                              u.StartsWith(@"STORAGE\") || (u.StartsWith(@"USB\") && u.Contains("&MI_"));
                if (!ascend) break;
                uint p;
                if (Native.CM_Get_Parent(out p, d, 0) != 0) break;
                d = p;
                id = GetId(d);
            }
            physId = id; physInst = d;
            return id != null;
        }

        /// <summary>Only external buses are guarded: USB and Bluetooth (not PS/2, RDP, virtual).</summary>
        public static bool IsGuardedBus(string physId)
        {
            if (physId == null) return false;
            string u = physId.ToUpperInvariant();
            return u.StartsWith(@"USB\") || u.StartsWith(@"BTHENUM\") || u.StartsWith(@"BTHLEDEVICE\");
        }

        static string RegProp(uint dev, uint prop)
        {
            uint type, len = 0;
            Native.CM_Get_DevNode_Registry_PropertyW(dev, prop, out type, null, ref len, 0);
            if (len == 0) return null;
            byte[] b = new byte[len];
            if (Native.CM_Get_DevNode_Registry_PropertyW(dev, prop, out type, b, ref len, 0) != 0) return null;
            string s = Encoding.Unicode.GetString(b).TrimEnd('\0');
            int z = s.IndexOf('\0');
            return z >= 0 ? s.Substring(0, z) : s;
        }

        static string StrProp(uint dev, Native.DEVPROPKEY key)
        {
            uint type, size = 0;
            Native.CM_Get_DevNode_PropertyW(dev, ref key, out type, null, ref size, 0);
            if (size == 0) return null;
            byte[] b = new byte[size];
            if (Native.CM_Get_DevNode_PropertyW(dev, ref key, out type, b, ref size, 0) != 0) return null;
            return Encoding.Unicode.GetString(b).TrimEnd('\0');
        }

        public static string GetName(uint dev)
        {
            if (dev == 0) return "Unknown device";
            string s = null;
            try { s = StrProp(dev, BusReportedDescKey); } catch { }
            if (string.IsNullOrEmpty(s)) s = RegProp(dev, CM_DRP_FRIENDLYNAME);
            if (string.IsNullOrEmpty(s)) s = RegProp(dev, CM_DRP_DEVICEDESC);
            string mfg = RegProp(dev, CM_DRP_MFG);
            if (!string.IsNullOrEmpty(mfg) && !mfg.StartsWith("(") && s != null && s.IndexOf(mfg, StringComparison.OrdinalIgnoreCase) < 0)
                s = s + " (" + mfg + ")";
            return string.IsNullOrEmpty(s) ? "Unknown device" : s;
        }

        /// <summary>Extracts "VID_xxxx PID_yyyy" from an instance id for display.</summary>
        public static string VidPid(string id)
        {
            if (id == null) return "";
            string u = id.ToUpperInvariant();
            int v = u.IndexOf("VID_"), p = u.IndexOf("PID_");
            string r = "";
            if (v >= 0 && v + 8 <= u.Length) r += "VID " + u.Substring(v + 4, 4);
            if (p >= 0 && p + 8 <= u.Length) r += "  PID " + u.Substring(p + 4, 4);
            return r;
        }

        /// <summary>
        /// Hardware + compatible IDs of a device node. HID collections carry their usage here,
        /// e.g. HID_DEVICE_SYSTEM_MOUSE / HID_DEVICE_UP:0001_U:0002 (mouse) or HID_DEVICE_UP:000D_U:0004 (touch screen).
        /// </summary>
        public static string[] CompatibleIds(string instanceId)
        {
            uint d = Locate(instanceId);
            var all = new List<string>();
            if (d == 0) return all.ToArray();
            foreach (uint prop in new uint[] { 0x02 /*CM_DRP_HARDWAREID*/, 0x03 /*CM_DRP_COMPATIBLEIDS*/ })
            {
                uint type, len = 0;
                Native.CM_Get_DevNode_Registry_PropertyW(d, prop, out type, null, ref len, 0);
                if (len == 0) continue;
                byte[] b = new byte[len];
                if (Native.CM_Get_DevNode_Registry_PropertyW(d, prop, out type, b, ref len, 0) != 0) continue;
                all.AddRange(Encoding.Unicode.GetString(b).Split(new[] { '\0' }, StringSplitOptions.RemoveEmptyEntries));
            }
            return all.ToArray();
        }

        /// <summary>What a HID collection is, from its usage IDs: "keyboard", "mouse", "digitizer" or null.</summary>
        public static string ClassifyHid(string instanceId)
        {
            foreach (string c in CompatibleIds(instanceId))
            {
                string u = c.ToUpperInvariant();
                if (u == "HID_DEVICE_SYSTEM_KEYBOARD" || u.StartsWith("HID_DEVICE_UP:0001_U:0006")) return "keyboard";
                if (u == "HID_DEVICE_SYSTEM_MOUSE" || u.StartsWith("HID_DEVICE_UP:0001_U:0002")) return "mouse";
                if (u.StartsWith("HID_DEVICE_UP:000D")) return "digitizer";
            }
            return null;
        }

        /// <summary>Physical USB device behind a drive letter, or null.</summary>
        public static string PhysForDrive(char letter)
        {
            int num = GetStorageDeviceNumber(@"\\.\" + letter + ":");
            if (num < 0) return null;
            foreach (string path in GetPresentInterfaces(Native.GUID_DEVINTERFACE_DISK))
            {
                if (GetStorageDeviceNumber(path) != num) continue;
                string phys; uint pi;
                if (ResolvePhysical(InstanceIdFromInterface(path), out phys, out pi) && phys.StartsWith(@"USB\", StringComparison.OrdinalIgnoreCase))
                    return phys;
                return null;
            }
            return null;
        }

        /// <summary>Disables one function of a device (e.g. only the mouse collection or the network adapter).</summary>
        public static string DisableInstance(string instanceId)
        {
            return Disable(instanceId);
        }

        public static string EnableInstance(string instanceId)
        {
            return Enable(instanceId);
        }

        /// <summary>Disables the physical device (non-persistent; UsbGuard re-disables blocked devices on re-plug).</summary>
        public static string Disable(string physId)
        {
            uint d = Locate(physId);
            if (d == 0) return "device not present";
            string svc = RegProp(d, CM_DRP_SERVICE) ?? "";
            if (physId.ToUpperInvariant().Contains("ROOT_HUB") || svc.ToLowerInvariant().StartsWith("usbhub"))
                return "refusing to disable a USB hub";
            int cr = Native.CM_Disable_DevNode(d, CM_DISABLE_ABSOLUTE | CM_DISABLE_UI_NOT_OK);
            if (cr == 0) return null;
            if (cr == 0x33) return "access denied (run as administrator)";
            if (cr == CR_NOT_DISABLEABLE) return NotDisableableText;
            return "CM_Disable_DevNode failed, CR=0x" + cr.ToString("X");
        }

        const int CR_NOT_DISABLEABLE = 0x28;
        public const string NotDisableableText = "Windows does not allow this device to be switched off";

        /// <summary>
        /// Blocks a whole physical device: disables it, or, when Windows marks it as not disableable
        /// (common for HID keyboards and wireless receivers), removes it like "Safely remove hardware"
        /// without restarting it. It stays off until it is unplugged; on re-plug the block list removes it again.
        /// </summary>
        public static string DisableOrRemove(string physId)
        {
            string err = Disable(physId);
            if (err != NotDisableableText) return err;
            uint d = Locate(physId);
            if (d == 0) return "device not present";
            int veto;
            StringBuilder vetoName = new StringBuilder(512);
            int cr = Native.CM_Query_And_Remove_SubTreeW(d, out veto, vetoName, vetoName.Capacity,
                0x1 /*CM_REMOVE_UI_NOT_OK*/ | 0x2 /*CM_REMOVE_NO_RESTART*/);
            if (cr == 0) return null;
            if (cr == 0x17 /*CR_REMOVE_VETOED*/)
                return err + ", and removing it was refused (veto " + veto + (vetoName.Length > 0 ? ": " + vetoName : "") + ")";
            return err + ", and removing it failed (CR=0x" + cr.ToString("X") + ")";
        }

        public static string Enable(string physId)
        {
            uint d = Locate(physId);
            if (d == 0) return "device not present";
            int cr = Native.CM_Enable_DevNode(d, 0);
            return cr == 0 ? null : "CM_Enable_DevNode failed, CR=0x" + cr.ToString("X");
        }

        public static int GetStorageDeviceNumber(string path)
        {
            try
            {
                using (var h = Native.CreateFile(path, 0, 3 /*share r/w*/, IntPtr.Zero, 3 /*OPEN_EXISTING*/, 0, IntPtr.Zero))
                {
                    if (h.IsInvalid) return -1;
                    Native.STORAGE_DEVICE_NUMBER n;
                    uint ret;
                    if (Native.DeviceIoControl(h, Native.IOCTL_STORAGE_GET_DEVICE_NUMBER, IntPtr.Zero, 0, out n,
                        (uint)Marshal.SizeOf(typeof(Native.STORAGE_DEVICE_NUMBER)), out ret, IntPtr.Zero))
                        return n.DeviceNumber;
                }
            }
            catch { }
            return -1;
        }

        public static List<string> GetPresentInterfaces(Guid cls)
        {
            var result = new List<string>();
            uint len;
            if (Native.CM_Get_Device_Interface_List_SizeW(out len, ref cls, null, 0) != 0 || len <= 1) return result;
            char[] buf = new char[len];
            if (Native.CM_Get_Device_Interface_ListW(ref cls, null, buf, len, 0) != 0) return result;
            foreach (string s in new string(buf).Split('\0'))
                if (s.Length > 0) result.Add(s);
            return result;
        }

        // ---- raw input device helpers ----
        public static uint RawDeviceType(IntPtr h)
        {
            uint size = 32;
            IntPtr buf = Marshal.AllocHGlobal(64);
            try
            {
                Marshal.WriteInt32(buf, 32); // RID_DEVICE_INFO.cbSize
                if ((int)Native.GetRawInputDeviceInfo(h, Native.RIDI_DEVICEINFO, buf, ref size) <= 0) return 0xFFFFFFFF;
                return (uint)Marshal.ReadInt32(buf, 4);
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        public static string RawDeviceName(IntPtr h)
        {
            uint size = 0;
            Native.GetRawInputDeviceInfo(h, Native.RIDI_DEVICENAME, IntPtr.Zero, ref size);
            if (size == 0) return null;
            IntPtr buf = Marshal.AllocHGlobal((int)size * 2 + 2);
            try
            {
                if ((int)Native.GetRawInputDeviceInfo(h, Native.RIDI_DEVICENAME, buf, ref size) <= 0) return null;
                return Marshal.PtrToStringUni(buf);
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        public static List<IntPtr> RawKeyboards()
        {
            var list = new List<IntPtr>();
            uint n = 0, cb = (uint)Marshal.SizeOf(typeof(Native.RAWINPUTDEVICELIST));
            Native.GetRawInputDeviceList(null, ref n, cb);
            if (n == 0) return list;
            var arr = new Native.RAWINPUTDEVICELIST[n];
            uint got = Native.GetRawInputDeviceList(arr, ref n, cb);
            if (got == 0xFFFFFFFF) return list;
            for (int i = 0; i < got; i++)
                if (arr[i].dwType == Native.RIM_TYPEKEYBOARD) list.Add(arr[i].hDevice);
            return list;
        }
    }
}
