using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using Microsoft.Win32;

namespace UsbGuard
{
    /// <summary>
    /// Small helper that changes DWORD registry values and remembers the original values in a state file,
    /// so a protection can be switched off again and the system is restored exactly.
    /// </summary>
    internal class RegBackup
    {
        readonly string stateFile;
        readonly List<string> lines = new List<string>();

        public RegBackup(string name) { stateFile = Path.Combine(Guard.DataDir, name); }

        public bool Exists { get { return File.Exists(stateFile); } }

        static RegistryKey Base(string view)
        {
            return RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view == "32" ? RegistryView.Registry32 : RegistryView.Registry64);
        }

        public void SetDword(string view, string path, string name, int value)
        {
            using (var b = Base(view))
            using (var k = b.CreateSubKey(path))
            {
                object old = k.GetValue(name);
                lines.Add("REG\t" + view + "\t" + path + "\t" + name + "\t" + (old is int ? "DW:" + (int)old : "ABSENT"));
                k.SetValue(name, value, RegistryValueKind.DWord);
            }
        }

        /// <summary>Adds a string value to a policy list subkey (values named 1,2,3,...), unless already listed.</summary>
        public void AddListEntry(string path, string entry)
        {
            using (var b = Base("64"))
            using (var k = b.CreateSubKey(path))
            {
                int max = 0;
                foreach (string n in k.GetValueNames())
                {
                    if (string.Equals(k.GetValue(n) as string, entry, StringComparison.OrdinalIgnoreCase)) return;
                    int i;
                    if (int.TryParse(n, out i) && i > max) max = i;
                }
                string name = (max + 1).ToString();
                k.SetValue(name, entry, RegistryValueKind.String);
                lines.Add("LIST\t" + path + "\t" + name);
            }
        }

        public void Custom(string line) { lines.Add(line); }

        public void Commit() { File.WriteAllLines(stateFile, lines.ToArray(), Encoding.UTF8); }

        /// <summary>Restores everything (in reverse order); custom lines are passed to the callback.</summary>
        public void Restore(Action<string[]> custom)
        {
            if (!Exists) return;
            string[] all = File.ReadAllLines(stateFile, Encoding.UTF8);
            foreach (string line in all.Reverse())
            {
                string[] p = line.Split('\t');
                try
                {
                    if (p[0] == "REG" && p.Length >= 5)
                    {
                        using (var b = Base(p[1]))
                        using (var k = b.CreateSubKey(p[2]))
                        {
                            if (p[4].StartsWith("DW:")) k.SetValue(p[3], int.Parse(p[4].Substring(3)), RegistryValueKind.DWord);
                            else k.DeleteValue(p[3], false);
                        }
                    }
                    else if (p[0] == "LIST" && p.Length >= 3)
                    {
                        using (var b = Base("64"))
                        using (var k = b.OpenSubKey(p[1], true))
                            if (k != null) k.DeleteValue(p[2], false);
                    }
                    else if (custom != null) custom(p);
                }
                catch (Exception ex) { Guard.Log("Restore failed for '" + line + "': " + ex.Message); }
            }
            File.Delete(stateFile);
        }
    }

    // =====================================================================
    /// <summary>
    /// Windows Device Installation Restrictions policy: Windows itself refuses to install drivers for
    /// new USB network adapters (RNDIS / CDC-ECM / NCM / EEM). Works before logon and on the lock screen.
    /// Adapters connected right now stay allowed.
    /// </summary>
    internal static class DeviceInstallPolicy
    {
        const string R = @"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions";

        // Matched against hardware and compatible IDs of each USB interface.
        public static readonly string[] DenyIds =
        {
            @"USB\Class_02&SubClass_06",            // CDC ECM (Ethernet)
            @"USB\Class_02&SubClass_0C",            // CDC EEM
            @"USB\Class_02&SubClass_0D",            // CDC NCM
            @"USB\Class_02&SubClass_02&Prot_FF",    // RNDIS (Linux gadget / Bash Bunny / P4wnP1 / PoisonTap)
            @"USB\Class_E0&SubClass_01&Prot_03",    // RNDIS (wireless controller class)
            @"USB\Class_EF&SubClass_04&Prot_01",    // RNDIS (misc class)
        };

        static readonly RegBackup state = new RegBackup("devinstall.state");

        public static bool IsEnabled() { return state.Exists; }

        public static List<string> CurrentUsbAdapters()
        {
            var list = new List<string>();
            foreach (string path in Dev.GetPresentInterfaces(Native.GUID_DEVINTERFACE_NET))
            {
                string inst = Dev.InstanceIdFromInterface(path);
                string phys; uint pi;
                if (Dev.ResolvePhysical(inst, out phys, out pi) && phys.StartsWith(@"USB\", StringComparison.OrdinalIgnoreCase))
                    list.Add(inst);
            }
            return list;
        }

        public static void Enable()
        {
            var b = new RegBackup("devinstall.state");
            b.SetDword("64", R, "DenyDeviceIDs", 1);
            b.SetDword("64", R, "DenyDeviceIDsRetroactive", 0);
            foreach (string id in DenyIds) b.AddListEntry(R + @"\DenyDeviceIDs", id);

            // Keep adapters that are connected now (docking station, your own dongle) working.
            var keep = CurrentUsbAdapters();
            if (keep.Count > 0)
            {
                b.SetDword("64", R, "AllowDenyLayered", 1);  // instance-ID allow beats device-ID deny
                b.SetDword("64", R, "AllowInstanceIDs", 1);
                foreach (string inst in keep) b.AddListEntry(R + @"\AllowInstanceIDs", inst);
            }
            b.Commit();
            Guard.Log("Device installation policy ON: new USB network adapters cannot be installed. Kept: " +
                      (keep.Count == 0 ? "none" : string.Join(", ", keep)));
        }

        public static void Disable()
        {
            state.Restore(null);
            Guard.Log("Device installation policy OFF: USB network adapters can be installed again.");
        }
    }

    // =====================================================================
    /// <summary>
    /// Removes the protocols a rogue network adapter abuses to steal NTLM hashes or hijack traffic:
    /// LLMNR, NetBIOS name broadcasts, WinHTTP WPAD; requires SMB signing; and blocks all inbound
    /// connections on Public (= unidentified) networks.
    /// </summary>
    internal static class NetHardening
    {
        static readonly RegBackup state = new RegBackup("nethardening.state");
        const string NetBT = @"SYSTEM\CurrentControlSet\Services\NetBT\Parameters";
        const int NET_FW_PROFILE2_PUBLIC = 4;

        public static bool IsEnabled() { return state.Exists; }

        public static void Enable()
        {
            var b = new RegBackup("nethardening.state");
            // LLMNR off
            b.SetDword("64", @"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableMulticast", 0);
            // NetBIOS: P-node = never broadcast name queries (stops NBT-NS poisoning even if DHCP re-enables NetBIOS)
            b.SetDword("64", NetBT, "NodeType", 2);
            using (var hk = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
            using (var ifs = hk.OpenSubKey(NetBT + @"\Interfaces"))
                if (ifs != null)
                    foreach (string sub in ifs.GetSubKeyNames())
                        b.SetDword("64", NetBT + @"\Interfaces\" + sub, "NetbiosOptions", 2); // disable NetBIOS over TCP/IP
            // WPAD (automatic proxy discovery) off for WinHTTP, 64- and 32-bit
            b.SetDword("64", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp", "DisableWpad", 1);
            b.SetDword("32", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp", "DisableWpad", 1);
            // SMB client must sign (stops NTLM relay through a rogue adapter)
            b.SetDword("64", @"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters", "RequireSecuritySignature", 1);
            // Firewall: Public profile blocks ALL inbound, even for allowed apps
            try
            {
                bool old = GetBlockAllInbound();
                SetBlockAllInbound(true);
                b.Custom("FW\t" + (old ? "1" : "0"));
            }
            catch (Exception ex) { Guard.Log("Firewall change failed: " + ex.Message); }
            b.Commit();
            Guard.Log("Network hardening ON (LLMNR, NetBIOS, WPAD off; SMB signing; Public profile blocks inbound). Reboot recommended.");
        }

        public static void Disable()
        {
            state.Restore(p =>
            {
                if (p[0] == "FW" && p.Length > 1) SetBlockAllInbound(p[1] == "1");
            });
            Guard.Log("Network hardening OFF - original settings restored. Reboot recommended.");
        }

        static object Fw()
        {
            return Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
        }

        static bool GetBlockAllInbound()
        {
            object fw = Fw();
            return (bool)fw.GetType().InvokeMember("BlockAllInboundTraffic", BindingFlags.GetProperty, null, fw, new object[] { NET_FW_PROFILE2_PUBLIC });
        }

        static void SetBlockAllInbound(bool v)
        {
            object fw = Fw();
            fw.GetType().InvokeMember("BlockAllInboundTraffic", BindingFlags.SetProperty, null, fw, new object[] { NET_FW_PROFILE2_PUBLIC, v });
        }
    }
}
