using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace UsbGuard
{
    internal class KeyRecord
    {
        public int Vk;
        public bool IsDown, Repeat, Injected;
        public uint Time;      // ms timestamp from the input system
        public string Text;    // human readable form of what would have been typed, or null
    }

    internal class MouseRecord
    {
        public string Kind;    // LCLICK, RCLICK, MCLICK, XCLICK, WHEEL, MOVE, JUMP
        public int X, Y, Dist;
        public uint Time;
        public bool Injected;
    }

    /// <summary>
    /// Global low-level keyboard hook on a dedicated high-priority thread that does nothing else,
    /// so it never hits the LowLevelHooksTimeout (which would let keys through).
    /// While Guard.Lockdown is set every keystroke is swallowed and reported via KeyBlocked.
    /// </summary>
    internal static class KeyHook
    {
        static readonly Native.LowLevelKeyboardProc proc = HookProc; // keep delegate alive
        static IntPtr hook;
        public static event Action<KeyRecord> KeyBlocked;

        static readonly bool[] down = new bool[256];       // physical state as we saw it
        static readonly bool[] sysDown = new bool[256];    // key-downs that the system actually received
        static bool shift, ctrl, alt, win, winCombo;
        static readonly byte[] keyState = new byte[256];
        static readonly StringBuilder buf = new StringBuilder(16);

        // ---- mouse ----
        static readonly Native.LowLevelKeyboardProc mproc = MouseProc; // same signature as the keyboard proc
        static IntPtr mhook;
        public static event Action<MouseRecord> MouseBlocked;
        static readonly bool[] sysBtn = new bool[4]; // L R M X buttons the system saw go down
        static int moveAccum;
        static uint lastMoveReport;

        public static void Start()
        {
            var ready = new ManualResetEvent(false);
            var t = new Thread(() =>
            {
                IntPtr mod = Native.GetModuleHandle(null);
                hook = Native.SetWindowsHookEx(Native.WH_KEYBOARD_LL, proc, mod, 0);
                mhook = Native.SetWindowsHookEx(Native.WH_MOUSE_LL, mproc, mod, 0);
                ready.Set();
                Application.Run();
            });
            t.Name = "InputHooks";
            t.IsBackground = true;
            t.Priority = ThreadPriority.Highest;
            t.SetApartmentState(ApartmentState.STA);
            t.Start();
            ready.WaitOne();
            if (hook == IntPtr.Zero) throw new InvalidOperationException("SetWindowsHookEx(keyboard) failed");
            if (mhook == IntPtr.Zero) Guard.Log("WARNING: mouse hook could not be installed");
        }

        static int ButtonIndex(int msg, out bool isDown)
        {
            isDown = false;
            switch (msg)
            {
                case Native.WM_LBUTTONDOWN: isDown = true; return 0;
                case Native.WM_LBUTTONUP: return 0;
                case Native.WM_RBUTTONDOWN: isDown = true; return 1;
                case Native.WM_RBUTTONUP: return 1;
                case Native.WM_MBUTTONDOWN: isDown = true; return 2;
                case Native.WM_MBUTTONUP: return 2;
                case Native.WM_XBUTTONDOWN: isDown = true; return 3;
                case Native.WM_XBUTTONUP: return 3;
            }
            return -1;
        }

        static IntPtr MouseProc(int nCode, IntPtr wParam, IntPtr lParam)
        {
            if (nCode < 0) return Native.CallNextHookEx(mhook, nCode, wParam, lParam);
            int msg = wParam.ToInt32();
            bool isDown;
            int btn = ButtonIndex(msg, out isDown);

            if (!Guard.MouseLockdown)
            {
                if (btn >= 0) sysBtn[btn] = isDown;
                return Native.CallNextHookEx(mhook, nCode, wParam, lParam);
            }

            // Let button-ups through for buttons the system saw go down (no stuck drag).
            if (btn >= 0 && !isDown && sysBtn[btn])
            {
                sysBtn[btn] = false;
                return Native.CallNextHookEx(mhook, nCode, wParam, lParam);
            }

            try
            {
                var m = (Native.MSLLHOOKSTRUCT)Marshal.PtrToStructure(lParam, typeof(Native.MSLLHOOKSTRUCT));
                MouseRecord rec = null;
                if (btn >= 0 && isDown)
                    rec = new MouseRecord { Kind = new[] { "LCLICK", "RCLICK", "MCLICK", "XCLICK" }[btn], X = m.pt.x, Y = m.pt.y };
                else if (msg == Native.WM_MOUSEWHEEL || msg == Native.WM_MOUSEHWHEEL)
                    rec = new MouseRecord { Kind = "WHEEL", X = m.pt.x, Y = m.pt.y };
                else if (msg == Native.WM_MOUSEMOVE)
                {
                    // The cursor does not move while blocked, so pt - cursor = this event's movement.
                    Native.POINT cur;
                    Native.GetCursorPos(out cur);
                    int dx = m.pt.x - cur.x, dy = m.pt.y - cur.y;
                    int dist = (int)Math.Sqrt((double)dx * dx + (double)dy * dy);
                    if (dist > 300)
                        rec = new MouseRecord { Kind = "JUMP", X = m.pt.x, Y = m.pt.y, Dist = dist };
                    else
                    {
                        moveAccum += dist;
                        if (m.time - lastMoveReport > 250 && moveAccum > 0)
                        {
                            rec = new MouseRecord { Kind = "MOVE", Dist = moveAccum };
                            moveAccum = 0;
                            lastMoveReport = m.time;
                        }
                    }
                }
                if (rec != null)
                {
                    rec.Time = m.time;
                    rec.Injected = (m.flags & Native.LLMHF_INJECTED) != 0;
                    var h = MouseBlocked;
                    if (h != null) h(rec);
                }
            }
            catch { }
            return (IntPtr)1;
        }

        static IntPtr HookProc(int nCode, IntPtr wParam, IntPtr lParam)
        {
            if (nCode < 0) return Native.CallNextHookEx(hook, nCode, wParam, lParam);

            var k = (Native.KBDLLHOOKSTRUCT)Marshal.PtrToStructure(lParam, typeof(Native.KBDLLHOOKSTRUCT));
            int msg = wParam.ToInt32();
            bool isDown = msg == Native.WM_KEYDOWN || msg == Native.WM_SYSKEYDOWN;
            int vk = (int)(k.vkCode & 0xFF);
            bool repeat = isDown && down[vk];
            down[vk] = isDown;

            bool wasWinCombo = winCombo;
            UpdateModifiers(vk, isDown);

            if (!Guard.Lockdown)
            {
                sysDown[vk] = isDown;
                return Native.CallNextHookEx(hook, nCode, wParam, lParam);
            }

            // Lockdown: let key-UPs through for keys the system saw go down (avoids stuck Win/Shift),
            // everything else is swallowed.
            bool passUp = !isDown && sysDown[vk];
            if (passUp) sysDown[vk] = false;

            try
            {
                string text = null;
                if (isDown && !repeat) text = Describe(vk, k.scanCode);
                else if (!isDown && (vk == 0x5B || vk == 0x5C) && !wasWinCombo) text = "[WIN]";

                if (isDown || text != null)
                {
                    var h = KeyBlocked;
                    if (h != null)
                        h(new KeyRecord
                        {
                            Vk = vk, IsDown = isDown, Repeat = repeat, Time = k.time, Text = text,
                            Injected = (k.flags & Native.LLKHF_INJECTED) != 0
                        });
                }
            }
            catch { }

            return passUp ? Native.CallNextHookEx(hook, nCode, wParam, lParam) : (IntPtr)1;
        }

        static void UpdateModifiers(int vk, bool isDown)
        {
            switch (vk)
            {
                case 0x10: case 0xA0: case 0xA1: shift = isDown; return;
                case 0x11: case 0xA2: case 0xA3: ctrl = isDown; return;
                case 0x12: case 0xA4: case 0xA5: alt = isDown; return;
                case 0x5B: case 0x5C: win = isDown; if (isDown) winCombo = false; return;
            }
            if (isDown && win) winCombo = true;
        }

        static bool IsModifier(int vk)
        {
            return vk == 0x10 || vk == 0x11 || vk == 0x12 || (vk >= 0xA0 && vk <= 0xA5) || vk == 0x5B || vk == 0x5C;
        }

        static string KeyName(int vk)
        {
            switch (vk)
            {
                case 0x08: return "BKSP";
                case 0x09: return "TAB";
                case 0x0D: return "ENTER";
                case 0x13: return "PAUSE";
                case 0x14: return "CAPS";
                case 0x1B: return "ESC";
                case 0x20: return "SPACE";
                case 0x21: return "PGUP";
                case 0x22: return "PGDN";
                case 0x23: return "END";
                case 0x24: return "HOME";
                case 0x25: return "←";
                case 0x26: return "↑";
                case 0x27: return "→";
                case 0x28: return "↓";
                case 0x2C: return "PRTSC";
                case 0x2D: return "INS";
                case 0x2E: return "DEL";
                case 0x5D: return "MENU";
            }
            if (vk >= 0x70 && vk <= 0x87) return "F" + (vk - 0x6F);
            if ((vk >= 0x30 && vk <= 0x39) || (vk >= 0x41 && vk <= 0x5A)) return ((char)vk).ToString();
            uint ch = Native.MapVirtualKey((uint)vk, 2) & 0x7FFF;
            if (ch > 0x20) return ((char)ch).ToString().ToUpperInvariant();
            return "VK_" + vk.ToString("X2");
        }

        /// <summary>Text representation of a blocked key-down, e.g. "c", "[WIN+R]", "[ENTER]\n".</summary>
        static string Describe(int vk, uint scan)
        {
            if (IsModifier(vk)) return null;

            if (ctrl || alt || win)
            {
                string p = (ctrl ? "CTRL+" : "") + (alt ? "ALT+" : "") + (win ? "WIN+" : "") + (shift ? "SHIFT+" : "");
                return "[" + p + KeyName(vk) + "]";
            }
            if (vk == 0x0D) return "[ENTER]\r\n";
            if (vk == 0x20) return " ";

            Array.Clear(keyState, 0, 256);
            if (shift) { keyState[0x10] = 0x80; keyState[0xA0] = 0x80; }
            if ((Native.GetKeyState(0x14) & 1) != 0) keyState[0x14] = 1;
            IntPtr hkl = Native.GetKeyboardLayout(Native.GetWindowThreadProcessId(Native.GetForegroundWindow(), IntPtr.Zero));
            buf.Length = 0;
            // flag 0x4: do not change the keyboard (dead-key) state
            int n = Native.ToUnicodeEx((uint)vk, scan, keyState, buf, 8, 0x4, hkl);
            if (n > 0)
            {
                string s = buf.ToString(0, Math.Min(n, buf.Length));
                if (s.Length > 0 && !char.IsControl(s[0])) return s;
            }
            return "[" + KeyName(vk) + "]";
        }
    }
}
