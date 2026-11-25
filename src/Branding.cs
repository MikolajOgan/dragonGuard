using System.Drawing;
using System.Reflection;

[assembly: AssemblyTitle("DragonGuard")]
[assembly: AssemblyProduct("DragonGuard")]
[assembly: AssemblyDescription("Protects against BadUSB keyboards, mice, rogue network adapters and malicious USB drives.")]
[assembly: AssemblyVersion("1.0.0.0")]
[assembly: AssemblyFileVersion("1.0.0.0")]

namespace UsbGuard
{
    /// <summary>
    /// Display name, icon and logo. Internal identifiers (service name, pipe, folders, exe name) stay "UsbGuard"
    /// so existing installations update in place and keep their device lists.
    /// </summary>
    internal static class Branding
    {
        public const string Name = "DragonGuard";

        static Icon icon;
        static Image logo;

        /// <summary>Embedded multi-size icon (assets\DragonGuard.ico); falls back to the system shield.</summary>
        public static Icon Icon
        {
            get
            {
                if (icon == null)
                    try { using (var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("DragonGuard.ico")) if (s != null) icon = new Icon(s); }
                    catch { }
                return icon ?? SystemIcons.Shield;
            }
        }

        /// <summary>Tray icon at the small-icon size of the current DPI.</summary>
        public static Icon SmallIcon
        {
            get
            {
                try
                {
                    var sz = System.Windows.Forms.SystemInformation.SmallIconSize;
                    using (var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("DragonGuard.ico"))
                        if (s != null) return new Icon(s, sz);
                }
                catch { }
                return Icon;
            }
        }

        /// <summary>Logo for the approval window header (assets\logo.png), or null.</summary>
        public static Image Logo
        {
            get
            {
                if (logo == null)
                    try { using (var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("DragonGuard.logo.png")) if (s != null) logo = new Bitmap(Image.FromStream(s)); }
                    catch { }
                return logo;
            }
        }
    }
}
