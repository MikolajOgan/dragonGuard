using System;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace UsbGuard
{
    internal static class Native
    {
        // ---- messages / constants ----
        public const int WH_KEYBOARD_LL = 13;
        public const int WM_KEYDOWN = 0x0100, WM_KEYUP = 0x0101, WM_SYSKEYDOWN = 0x0104, WM_SYSKEYUP = 0x0105;
        public const int WM_INPUT_DEVICE_CHANGE = 0x00FE, WM_INPUT = 0x00FF, WM_DEVICECHANGE = 0x0219;
        public const int GIDC_ARRIVAL = 1, GIDC_REMOVAL = 2;
        public const int DBT_DEVICEARRIVAL = 0x8000, DBT_DEVICEREMOVECOMPLETE = 0x8004;
        public const int DBT_DEVTYP_VOLUME = 2, DBT_DEVTYP_DEVICEINTERFACE = 5;
        public const uint LLKHF_INJECTED = 0x10;

        public const uint RIDEV_INPUTSINK = 0x00000100, RIDEV_DEVNOTIFY = 0x00002000;
        public const uint RID_HEADER = 0x10000005;
        public const uint RIDI_DEVICENAME = 0x20000007, RIDI_DEVICEINFO = 0x2000000b;
        public const uint RIM_TYPEKEYBOARD = 1;

        public static readonly Guid GUID_DEVINTERFACE_DISK = new Guid("53f56307-b6bf-11d0-94f2-00a0c91efb8b");
        public static readonly Guid GUID_DEVINTERFACE_NET = new Guid("cac88484-7515-4c03-82e6-71a87abac361");
        public static readonly Guid GUID_DEVINTERFACE_HID = new Guid("4d1e55b2-f16f-11cf-88cb-001111000030");

        // ---- mouse hook ----
        public const int WH_MOUSE_LL = 14;
        public const int WM_MOUSEMOVE = 0x0200, WM_LBUTTONDOWN = 0x0201, WM_LBUTTONUP = 0x0202,
                         WM_RBUTTONDOWN = 0x0204, WM_RBUTTONUP = 0x0205, WM_MBUTTONDOWN = 0x0207, WM_MBUTTONUP = 0x0208,
                         WM_MOUSEWHEEL = 0x020A, WM_XBUTTONDOWN = 0x020B, WM_XBUTTONUP = 0x020C, WM_MOUSEHWHEEL = 0x020E;
        public const uint LLMHF_INJECTED = 0x1;

        [StructLayout(LayoutKind.Sequential)]
        public struct POINT { public int x, y; }

        [StructLayout(LayoutKind.Sequential)]
        public struct MSLLHOOKSTRUCT
        {
            public POINT pt;
            public uint mouseData, flags, time;
            public IntPtr dwExtraInfo;
        }

        [DllImport("user32.dll")]
        public static extern bool GetCursorPos(out POINT p);

        // ---- PnP notifications without a window (works in a service) ----
        [StructLayout(LayoutKind.Sequential)]
        public struct CM_NOTIFY_FILTER
        {
            public int cbSize, Flags, FilterType, Reserved;
            public Guid ClassGuid;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 384)]
            public byte[] Pad; // rest of the 400-byte union
        }

        public delegate int CM_NOTIFY_CALLBACK(IntPtr hNotify, IntPtr context, int action, IntPtr eventData, int size);
        public const int CM_NOTIFY_ACTION_DEVICEINTERFACEARRIVAL = 0, CM_NOTIFY_ACTION_DEVICEINTERFACEREMOVAL = 1;

        [DllImport("cfgmgr32.dll")]
        public static extern int CM_Register_Notification(ref CM_NOTIFY_FILTER filter, IntPtr context, CM_NOTIFY_CALLBACK cb, out IntPtr handle);

        // ---- sessions / tokens / processes ----
        [StructLayout(LayoutKind.Sequential)]
        public struct WTS_SESSION_INFO
        {
            public uint SessionId;
            public IntPtr pWinStationName;
            public int State; // 0 = WTSActive
        }

        [DllImport("kernel32.dll")]
        public static extern uint WTSGetActiveConsoleSessionId();

        [DllImport("wtsapi32.dll", SetLastError = true)]
        public static extern bool WTSQueryUserToken(uint sessionId, out IntPtr token);

        [DllImport("wtsapi32.dll", SetLastError = true)]
        public static extern bool WTSEnumerateSessions(IntPtr server, int reserved, int version, out IntPtr info, out int count);

        [DllImport("wtsapi32.dll")]
        public static extern void WTSFreeMemory(IntPtr p);

        public const uint TOKEN_ALL_ACCESS = 0xF01FF;
        public const int TokenSessionId = 12, TokenElevationType = 18, TokenLinkedToken = 19;

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool GetTokenInformation(IntPtr token, int cls, IntPtr info, int len, out int retLen);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool SetTokenInformation(IntPtr token, int cls, ref uint info, int len);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool DuplicateTokenEx(IntPtr existing, uint access, IntPtr attrs, int impLevel, int tokenType, out IntPtr newToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("userenv.dll", SetLastError = true)]
        public static extern bool CreateEnvironmentBlock(out IntPtr env, IntPtr token, bool inherit);

        [DllImport("userenv.dll")]
        public static extern bool DestroyEnvironmentBlock(IntPtr env);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public int cb;
            public string lpReserved, lpDesktop, lpTitle;
            public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
            public short wShowWindow, cbReserved2;
            public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess, hThread;
            public int dwProcessId, dwThreadId;
        }

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessAsUser(IntPtr token, string app, string cmd, IntPtr pa, IntPtr ta, bool inherit,
            uint flags, IntPtr env, string dir, ref STARTUPINFO si, out PROCESS_INFORMATION pi);

        [DllImport("kernel32.dll")]
        public static extern bool CloseHandle(IntPtr h);

        // ---- named pipes ----
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetNamedPipeClientSessionId(IntPtr pipe, out uint sessionId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetNamedPipeServerProcessId(IntPtr pipe, out uint pid);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool QueryFullProcessImageName(IntPtr process, int flags, StringBuilder name, ref int size);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);

        // ---- keyboard hook ----
        [StructLayout(LayoutKind.Sequential)]
        public struct KBDLLHOOKSTRUCT
        {
            public uint vkCode, scanCode, flags, time;
            public IntPtr dwExtraInfo;
        }

        public delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr SetWindowsHookEx(int idHook, LowLevelKeyboardProc fn, IntPtr hMod, uint threadId);

        [DllImport("user32.dll")]
        public static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        public static extern IntPtr GetModuleHandle(string name);

        // ---- raw input ----
        [StructLayout(LayoutKind.Sequential)]
        public struct RAWINPUTDEVICE
        {
            public ushort usUsagePage, usUsage;
            public uint dwFlags;
            public IntPtr hwndTarget;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct RAWINPUTDEVICELIST
        {
            public IntPtr hDevice;
            public uint dwType;
        }

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool RegisterRawInputDevices(RAWINPUTDEVICE[] devs, uint num, uint cbSize);

        [DllImport("user32.dll")]
        public static extern uint GetRawInputData(IntPtr hRawInput, uint cmd, IntPtr data, ref uint size, uint headerSize);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        public static extern uint GetRawInputDeviceInfo(IntPtr hDevice, uint cmd, IntPtr data, ref uint size);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern uint GetRawInputDeviceList([Out] RAWINPUTDEVICELIST[] list, ref uint num, uint cbSize);

        // ---- device notifications ----
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct DEV_BROADCAST_DEVICEINTERFACE
        {
            public int dbcc_size, dbcc_devicetype, dbcc_reserved;
            public Guid dbcc_classguid;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 255)]
            public string dbcc_name;
        }

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr RegisterDeviceNotification(IntPtr hRecipient, IntPtr filter, uint flags);

        // ---- configuration manager ----
        [StructLayout(LayoutKind.Sequential)]
        public struct DEVPROPKEY
        {
            public Guid fmtid;
            public uint pid;
            public DEVPROPKEY(Guid g, uint p) { fmtid = g; pid = p; }
        }

        [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
        public static extern int CM_Locate_DevNodeW(out uint devInst, string id, uint flags);

        [DllImport("cfgmgr32.dll")]
        public static extern int CM_Get_Parent(out uint parent, uint devInst, uint flags);

        [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
        public static extern int CM_Get_Device_IDW(uint devInst, StringBuilder buf, int len, uint flags);

        [DllImport("cfgmgr32.dll")]
        public static extern int CM_Disable_DevNode(uint devInst, uint flags);

        [DllImport("cfgmgr32.dll")]
        public static extern int CM_Enable_DevNode(uint devInst, uint flags);

        [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
        public static extern int CM_Query_And_Remove_SubTreeW(uint devInst, out int vetoType, StringBuilder vetoName, int nameLen, uint flags);

        [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
        public static extern int CM_Get_DevNode_Registry_PropertyW(uint devInst, uint prop, out uint type, byte[] buf, ref uint len, uint flags);

        [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
        public static extern int CM_Get_DevNode_PropertyW(uint devInst, ref DEVPROPKEY key, out uint type, byte[] buf, ref uint size, uint flags);

        [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
        public static extern int CM_Get_Device_Interface_PropertyW(string iface, ref DEVPROPKEY key, out uint type, byte[] buf, ref uint size, uint flags);

        [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
        public static extern int CM_Get_Device_Interface_List_SizeW(out uint len, ref Guid g, string devId, uint flags);

        [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
        public static extern int CM_Get_Device_Interface_ListW(ref Guid g, string devId, char[] buf, uint len, uint flags);

        // ---- storage ----
        [StructLayout(LayoutKind.Sequential)]
        public struct STORAGE_DEVICE_NUMBER
        {
            public int DeviceType, DeviceNumber, PartitionNumber;
        }

        public const uint IOCTL_STORAGE_GET_DEVICE_NUMBER = 0x002D1080;

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr sa, uint disposition, uint flags, IntPtr template);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool DeviceIoControl(SafeFileHandle h, uint code, IntPtr inBuf, uint inSize,
            out STORAGE_DEVICE_NUMBER outBuf, uint outSize, out uint returned, IntPtr overlapped);

        // ---- volumes / drive letters (pending USB drives are kept without a letter) ----
        public static readonly Guid GUID_DEVINTERFACE_VOLUME = new Guid("53f5630d-b6bf-11d0-94f2-00a0c91efb8b");

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool GetVolumeNameForVolumeMountPointW(string mountPoint, StringBuilder volumeName, int len);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool GetVolumePathNamesForVolumeNameW(string volumeName, char[] buf, int len, out int needed);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool DeleteVolumeMountPointW(string mountPoint);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool SetVolumeMountPointW(string mountPoint, string volumeName);

        [DllImport("kernel32.dll")]
        public static extern uint GetLogicalDrives();

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool GetVolumeInformationW(string root, StringBuilder label, int labelLen, out uint serial,
            out uint maxComponent, out uint fsFlags, StringBuilder fsName, int fsNameLen);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool GetDiskFreeSpaceExW(string dir, out ulong freeToCaller, out ulong total, out ulong totalFree);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct WIN32_FIND_DATA
        {
            public uint dwFileAttributes;
            public uint ftCreationLow, ftCreationHigh, ftAccessLow, ftAccessHigh, ftWriteLow, ftWriteHigh; // FILETIMEs (4-byte aligned)
            public uint nFileSizeHigh, nFileSizeLow, dwReserved0, dwReserved1;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string cFileName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 14)] public string cAlternateFileName;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr FindFirstFileW(string name, out WIN32_FIND_DATA data);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool FindNextFileW(IntPtr h, out WIN32_FIND_DATA data);

        [DllImport("kernel32.dll")]
        public static extern bool FindClose(IntPtr h);

        // ---- key translation ----
        [DllImport("user32.dll")]
        public static extern int ToUnicodeEx(uint vk, uint scan, byte[] state, [Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder buf, int cch, uint flags, IntPtr hkl);

        [DllImport("user32.dll")]
        public static extern IntPtr GetKeyboardLayout(uint threadId);

        [DllImport("user32.dll")]
        public static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll")]
        public static extern uint GetWindowThreadProcessId(IntPtr hwnd, IntPtr pid);

        [DllImport("user32.dll")]
        public static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint pid);

        [DllImport("user32.dll")]
        public static extern bool SetForegroundWindow(IntPtr hwnd);

        [DllImport("user32.dll")]
        public static extern IntPtr GetShellWindow();

        [DllImport("user32.dll")]
        public static extern short GetKeyState(int vk);

        [DllImport("user32.dll")]
        public static extern uint MapVirtualKey(uint code, uint mapType);

        [DllImport("user32.dll")]
        public static extern bool FlashWindow(IntPtr hwnd, bool invert);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        public static extern IntPtr FindWindow(string cls, string title);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        public static extern uint RegisterWindowMessage(string name);

        /// <summary>Process-wide UIPI filter: lets a lower-integrity process (Explorer) send us this message.</summary>
        [DllImport("user32.dll")]
        public static extern bool ChangeWindowMessageFilter(uint msg, uint flag);
        public const uint MSGFLT_ADD = 1;
    }
}
