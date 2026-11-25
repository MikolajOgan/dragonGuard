using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;

namespace UsbGuard
{
    /// <summary>Approval window for one physical device (all its keyboard/storage/network/pointer functions).</summary>
    internal class PromptForm : Form
    {
        const int SeqLen = 6;
        static readonly string[] Arrow = { "←", "↑", "→", "↓" }; // VK 0x25..0x28

        public readonly string Phys;
        public readonly string DevName;
        public readonly bool IsTest;
        public bool IsDecided { get; private set; }
        public bool DisableFailed { get; private set; }
        /// <summary>form, allow, mode: "1" remember, "0" until restart, "O" once (until unplugged).</summary>
        public event Action<PromptForm, bool, string> Decided;
        public event Action<PromptForm> UnlockRequested;

        readonly HashSet<string> keyboards = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        readonly HashSet<string> storages = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        readonly HashSet<string> networks = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        readonly HashSet<string> pointers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        readonly List<string> toEnable = new List<string>();
        readonly List<string> drives = new List<string>();   // "E:" or "no drive letter"
        readonly StringBuilder captured = new StringBuilder();
        readonly List<uint> keyTimes = new List<uint>();
        bool mouseHeld;
        bool driveLocked;    // the drive is kept without a drive letter until approval

        readonly Label lblIfaces, lblLock, lblDisabled, lblSeqHelp, lblStatus, lblInjection, lblNote, lblScanTitle;
        readonly FlowLayoutPanel seqPanel;
        readonly Label[] seqLabels = new Label[SeqLen];
        readonly TextBox txtKeys, txtScan;
        readonly RadioButton rbRemember, rbRestart, rbOnce;
        readonly Button btnAllow, btnBlock, btnUnlock;
        readonly Timer timer;

        int[] seq = new int[SeqLen];
        int pos, failures, blockedCount, jumps, clicks;
        DateTime cooldownUntil = DateTime.MinValue;
        bool injectionLock, mouseWarned, active;

        public bool HasKeyboard { get { return keyboards.Count > 0; } }
        public bool HasPointer { get { return pointers.Count > 0; } }
        /// <summary>Approval must come from the arrow sequence (a mouse click could come from the device itself).</summary>
        public bool NeedsArrows { get { return keyboards.Count > 0 || mouseHeld; } }
        public int InterfaceCount { get { return keyboards.Count + storages.Count + networks.Count + pointers.Count; } }
        public string CapturedText { get { return captured.ToString(); } }
        public IList<string> ToEnable { get { return toEnable; } }

        public PromptForm(string phys, string name, bool isTest)
        {
            Phys = phys; DevName = name; IsTest = isTest;

            SuspendLayout();
            AutoScaleDimensions = new SizeF(96F, 96F);
            AutoScaleMode = AutoScaleMode.Dpi;
            Font = new Font("Segoe UI", 9.75F);
            Text = "DragonGuard - new device needs approval";
            Icon = Branding.Icon;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false; MinimizeBox = false;
            StartPosition = FormStartPosition.Manual; // positioned in OnLoad so it fits the working area
            TopMost = true;
            ClientSize = new Size(980, 660);
            BackColor = Color.White;

            // Layout: header across the top, two columns (decision | evidence), options + buttons pinned at the bottom.
            var t = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 3, Padding = new Padding(16, 12, 16, 10) };
            t.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 54));
            t.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 46));
            t.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            t.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            t.RowStyles.Add(new RowStyle(SizeType.AutoSize));

            var title = Lbl((isTest ? "[TEST] " : "") + "New USB device connected", 15F, FontStyle.Bold, Color.FromArgb(32, 32, 32));
            var lblName = Lbl(name, 11F, FontStyle.Bold, Color.FromArgb(0, 84, 166));
            var lblId = Lbl(Dev.VidPid(phys) + "    " + phys, 8.5F, FontStyle.Regular, Color.DimGray);
            // Header: logo on the left, title / device name / id on the right.
            var header = new TableLayoutPanel { ColumnCount = 2, RowCount = 3, AutoSize = true, Anchor = AnchorStyles.Left | AnchorStyles.Right, Margin = new Padding(0, 0, 0, 6) };
            header.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            header.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            for (int i = 0; i < 3; i++) header.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            Image logo = Branding.Logo;
            if (logo != null)
            {
                var pic = new PictureBox { Image = logo, SizeMode = PictureBoxSizeMode.Zoom, Size = new Size(80, 80), Margin = new Padding(0, 0, 12, 0) };
                header.Controls.Add(pic, 0, 0);
                header.SetRowSpan(pic, 3);
            }
            header.Controls.Add(title, 1, 0);
            header.Controls.Add(lblName, 1, 1);
            header.Controls.Add(lblId, 1, 2);

            lblIfaces = Lbl("", 9.75F, FontStyle.Regular, Color.Black);
            lblNote =Lbl("", 9.75F, FontStyle.Bold, Color.DarkRed);
            lblNote.Visible = false;

            lblLock = Lbl("", 9.75F, FontStyle.Regular, Color.FromArgb(120, 0, 0));
            lblLock.BackColor = Color.FromArgb(255, 236, 236);
            lblLock.Padding = new Padding(8);

            lblDisabled = Lbl("", 9.75F, FontStyle.Regular, Color.FromArgb(0, 70, 0));
            lblDisabled.BackColor = Color.FromArgb(232, 246, 234);
            lblDisabled.Padding = new Padding(8);
            lblDisabled.Visible = false;

            lblSeqHelp = Lbl("", 10F, FontStyle.Bold, Color.Black);
            seqPanel = new FlowLayoutPanel { AutoSize = true, Anchor = AnchorStyles.None, Margin = new Padding(0, 4, 0, 4), WrapContents = false };
            for (int i = 0; i < SeqLen; i++)
            {
                seqLabels[i] = new Label
                {
                    AutoSize = false, Size = new Size(62, 62), TextAlign = ContentAlignment.MiddleCenter,
                    Font = new Font("Segoe UI Symbol", 26F, FontStyle.Bold), Margin = new Padding(4),
                    BorderStyle = BorderStyle.FixedSingle
                };
                seqPanel.Controls.Add(seqLabels[i]);
            }
            lblStatus = Lbl("", 9.75F, FontStyle.Regular, Color.DimGray);
            lblInjection = Lbl("", 10F, FontStyle.Bold, Color.White);
            lblInjection.BackColor = Color.FromArgb(192, 0, 0);
            lblInjection.Padding = new Padding(8);
            lblInjection.Visible = false;

            var lblKeysTitle = Lbl("Keystrokes / mouse actions blocked while waiting (what the device tried to do):", 9.75F, FontStyle.Bold, Color.Black);
            txtKeys = Box(90);
            lblScanTitle = Lbl("Storage / autorun scan:", 9.75F, FontStyle.Bold, Color.Black);
            txtScan = Box(110);
            txtScan.Text = "(no drive mounted yet)";

            var modePanel = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.TopDown, WrapContents = false, Margin = new Padding(3, 8, 3, 3), Anchor = AnchorStyles.Left | AnchorStyles.Bottom };
            rbRemember = new RadioButton { Text = "Remember my decision for this device", Checked = true, AutoSize = true };
            rbOnce = new RadioButton { Text = "Only this once - ask again after it is unplugged", AutoSize = true };
            rbRestart = new RadioButton { Text = "Only until the PC restarts", AutoSize = true };
            modePanel.Controls.AddRange(new Control[] { rbRemember, rbOnce, rbRestart });

            var buttons = new FlowLayoutPanel { AutoSize = true, Anchor = AnchorStyles.Right | AnchorStyles.Bottom, FlowDirection = FlowDirection.LeftToRight, WrapContents = false };
            btnUnlock = new Button { Text = "Unlock keyboard/mouse anyway", AutoSize = true, Visible = false, Padding = new Padding(6, 2, 6, 2) };
            btnBlock = new Button { Text = "Block device", AutoSize = true, Padding = new Padding(10, 4, 10, 4), BackColor = Color.FromArgb(192, 0, 0), ForeColor = Color.White, FlatStyle = FlatStyle.Flat };
            btnAllow = new Button { Text = "Allow", AutoSize = true, Padding = new Padding(10, 4, 10, 4) };
            buttons.Controls.AddRange(new Control[] { btnUnlock, btnBlock, btnAllow });

            btnBlock.Click += (s, e) => Decide(false);
            btnAllow.Click += (s, e) => { if (!NeedsArrows) Decide(true); };
            btnUnlock.Click += (s, e) => { var h = UnlockRequested; if (h != null) h(this); };

            // Left column: what the device is and how to approve it. Scrolls if the screen is very small.
            var left = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, Margin = new Padding(0, 0, 10, 0) };
            left.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            // Vertical scrolling only (labels wrap to the column width instead of scrolling sideways).
            left.HorizontalScroll.Maximum = 0;
            left.AutoScroll = false;
            left.HorizontalScroll.Visible = false;
            left.AutoScroll = true;
            foreach (Control c in new Control[] { lblIfaces, lblNote, lblLock, lblDisabled, lblSeqHelp, seqPanel, lblStatus, lblInjection })
            {
                left.RowCount++;
                left.RowStyles.Add(new RowStyle(SizeType.AutoSize));
                left.Controls.Add(c);
            }

            // Right column: what the device tried to do and what is on its drive; the boxes share the height.
            var right = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 4, Margin = new Padding(10, 0, 0, 0) };
            right.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            right.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            right.RowStyles.Add(new RowStyle(SizeType.Percent, 50));
            right.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            right.RowStyles.Add(new RowStyle(SizeType.Percent, 50));
            right.Controls.Add(lblKeysTitle, 0, 0);
            right.Controls.Add(txtKeys, 0, 1);
            right.Controls.Add(lblScanTitle, 0, 2);
            right.Controls.Add(txtScan, 0, 3);

            t.Controls.Add(header, 0, 0);
            t.SetColumnSpan(header, 2);
            t.Controls.Add(left, 0, 1);
            t.Controls.Add(right, 1, 1);
            t.Controls.Add(modePanel, 0, 2);
            t.Controls.Add(buttons, 1, 2);
            Controls.Add(t);
            ResumeLayout(false);
            PerformLayout();

            timer = new Timer { Interval = 250 };
            timer.Tick += (s, e) => RefreshStatus();
            timer.Start();

            NewSequence();
            UpdateView();
        }

        static Label Lbl(string text, float size, FontStyle style, Color color)
        {
            return new Label
            {
                Text = text, AutoSize = true, UseMnemonic = false, Anchor = AnchorStyles.Left | AnchorStyles.Right,
                Font = new Font("Segoe UI", size, style), ForeColor = color, Margin = new Padding(3, 3, 3, 3)
            };
        }

        static TextBox Box(int height)
        {
            return new TextBox
            {
                Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, Height = height,
                Dock = DockStyle.Fill, Font = new Font("Consolas", 9.5F), BackColor = Color.FromArgb(248, 248, 248), WordWrap = true
            };
        }

        // ---- keyboard focus ----
        // The window never takes keyboard focus (not when shown, not when clicked): keystrokes keep going to the
        // previously active app, where the low-level hook swallows them and reports them here. While this window
        // had focus, physical keys could miss the hook, so the captured text and the arrow approval stopped
        // working until the user clicked another window.
        const int WS_EX_NOACTIVATE = 0x08000000, WM_MOUSEACTIVATE = 0x0021, MA_NOACTIVATE = 3;
        const int WM_KEYDOWN = 0x0100, WM_SYSKEYDOWN = 0x0104;

        [System.Runtime.InteropServices.DllImport("user32.dll")]
        static extern int GetMessageTime();

        protected override bool ShowWithoutActivation { get { return true; } }

        protected override CreateParams CreateParams
        {
            get { var cp = base.CreateParams; cp.ExStyle |= WS_EX_NOACTIVATE; return cp; }
        }

        protected override void WndProc(ref Message m)
        {
            if (m.Msg == WM_MOUSEACTIVATE) { m.Result = (IntPtr)MA_NOACTIVATE; return; }
            base.WndProc(ref m);
        }

        /// <summary>
        /// Fallback: a key that reaches this window during lockdown was missed by the hook (the window got focus
        /// some other way). Handle it exactly like a hooked key instead of letting the controls eat it.
        /// </summary>
        protected override bool ProcessCmdKey(ref Message msg, Keys keyData)
        {
            if ((msg.Msg == WM_KEYDOWN || msg.Msg == WM_SYSKEYDOWN) && Guard.Lockdown && NeedsArrows && !IsDecided)
            {
                int vk = (int)(keyData & Keys.KeyCode);
                bool repeat = (msg.LParam.ToInt64() & 0x40000000) != 0;
                bool isArrow = vk >= 0x25 && vk <= 0x28;
                string text = isArrow ? null : vk == 0x0D ? "[ENTER]\r\n" : vk == 0x20 ? " " : vk == 0x1B ? "[ESC]" : "[" + (keyData & Keys.KeyCode) + "]";
                OnKey(new KeyRecord { Vk = vk, IsDown = true, Repeat = repeat, Time = (uint)GetMessageTime(), Text = repeat ? null : text });
                return true;
            }
            return base.ProcessCmdKey(ref msg, keyData);
        }

        /// <summary>Keeps the whole window (and so the buttons) inside the working area of the current screen.</summary>
        protected override void OnLoad(EventArgs e)
        {
            base.OnLoad(e);
            Rectangle wa = Screen.FromPoint(Cursor.Position).WorkingArea;
            Size = new Size(Math.Min(Width, wa.Width), Math.Min(Height, wa.Height));
            Location = new Point(wa.Left + (wa.Width - Width) / 2, wa.Top + (wa.Height - Height) / 2);
        }

        protected override void OnShown(EventArgs e)
        {
            base.OnShown(e);
            Native.FlashWindow(Handle, true);
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            if (!IsDecided && e.CloseReason == CloseReason.UserClosing)
            {
                e.Cancel = true;
                lblStatus.Visible = true;
                lblStatus.Text = "Please choose Allow or Block (closing the window would leave the device undecided).";
                lblStatus.ForeColor = Color.DarkRed;
            }
            base.OnFormClosing(e);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) timer.Dispose();
            base.Dispose(disposing);
        }

        // ------------------------------------------------------------------
        public void AddInterface(DeviceEvent e)
        {
            switch (e.Kind)
            {
                case IfaceKind.Keyboard: keyboards.Add(e.Path); break;
                case IfaceKind.Storage: storages.Add(e.Path); break;
                case IfaceKind.Network: networks.Add(e.Path); break;
                case IfaceKind.Pointer: pointers.Add(e.Path); break;
            }
            if (e.DisabledInst != null && !toEnable.Contains(e.DisabledInst)) toEnable.Add(e.DisabledInst);
            if (e.MouseHeld) mouseHeld = true;
            if (!string.IsNullOrEmpty(e.Note)) { lblNote.Text = e.Note; lblNote.Visible = true; }
            UpdateView();
        }

        public void RemoveInterface(string path)
        {
            keyboards.Remove(path);
            storages.Remove(path);
        }

        /// <summary>Returns false if this drive was already added.</summary>
        public bool AddDrive(string display, bool locked = false)
        {
            if (locked) driveLocked = true;
            bool added = !drives.Contains(display);
            if (added) drives.Add(display);
            UpdateView();
            return added;
        }

        public void SetScan(string display, ScanResult r)
        {
            string prefix = r.Suspicious ? "!! SUSPICIOUS CONTENT\r\n" : "";
            txtScan.Text = prefix + r.Report.Replace("\n", "\r\n").Replace("\r\r", "\r");
            if (r.Suspicious) { txtScan.BackColor = Color.FromArgb(255, 236, 236); lblScanTitle.ForeColor = Color.DarkRed; }
        }

        public void SetActive(bool isActive)
        {
            active = isActive;
            RefreshStatus();
        }

        public void ShowDisableFailed(string err)
        {
            DisableFailed = true;
            lblNote.Text = "Could not disable the device: " + err + "\r\nUNPLUG IT NOW. " +
                           (NeedsArrows ? "Keyboard/mouse input stays blocked until it is unplugged." : "");
            lblNote.Visible = true;
            btnUnlock.Visible = NeedsArrows;
            btnAllow.Enabled = btnBlock.Enabled = false;
        }

        void UpdateView()
        {
            var parts = new List<string>();
            if (keyboards.Count > 0) parts.Add("Keyboard" + (keyboards.Count > 1 ? " x" + keyboards.Count : ""));
            if (pointers.Count > 0) parts.Add("Mouse/pointer" + (pointers.Count > 1 ? " x" + pointers.Count : ""));
            if (networks.Count > 0) parts.Add("NETWORK ADAPTER");
            if (storages.Count > 0) parts.Add("Mass storage" + (drives.Count > 0 ? " (" + string.Join(", ", drives) + ")" : ""));
            int kinds = (keyboards.Count > 0 ? 1 : 0) + (pointers.Count > 0 ? 1 : 0) + (networks.Count > 0 ? 1 : 0) + (storages.Count > 0 ? 1 : 0);
            string warn = "";
            if (networks.Count > 0 && (keyboards.Count > 0 || storages.Count > 0))
                warn = "\r\n⚠ Network adapter combined with keyboard/storage is typical for attack gadgets (Bash Bunny, P4wnP1...).";
            else if (keyboards.Count > 0 && storages.Count > 0)
                warn = "\r\n⚠ Keyboard combined with storage is typical for attack gadgets.";
            lblIfaces.Text = "Functions: " + (parts.Count > 0 ? string.Join("  +  ", parts) : "-") + warn;

            // Lock banner
            var lockText = new List<string>();
            if (keyboards.Count > 0) lockText.Add("⚠  This device is a KEYBOARD. All keyboard input on this PC is blocked until you decide.");
            if (mouseHeld) lockText.Add("⚠  The new mouse could not be switched off, so ALL mouse input is blocked. Use the keyboard.");
            lblLock.Text = string.Join("\r\n", lockText) +
                           (lockText.Count > 0 ? "\r\nA legitimate device is harmless to approve; a BadUSB / \"rubber ducky\" is stopped here." : "");
            lblLock.Visible = lockText.Count > 0;

            // Disabled functions banner
            var dis = new List<string>();
            if (pointers.Count > 0 && !mouseHeld && toEnable.Count > 0) dis.Add("✔  The new mouse/pointer is switched off until you approve it - it cannot click or move. Your other mice keep working.");
            if (networks.Count > 0 && toEnable.Count > 0) dis.Add("✔  The new network adapter is switched off until you approve it (stops LAN Turtle / PoisonTap style traffic hijacking and password-hash theft).");
            if (storages.Count > 0 && driveLocked) dis.Add("✔  The drive has no drive letter until you approve it, so it can't be opened. Its contents are scanned on the right.");
            lblDisabled.Text = string.Join("\r\n", dis);
            lblDisabled.Visible = dis.Count > 0;

            bool arrows = NeedsArrows;
            lblSeqHelp.Visible = seqPanel.Visible = arrows;
            lblSeqHelp.Text = "To ALLOW it, press these arrow keys in order (on any keyboard).   " +
                              (keyboards.Count > 0 ? "To block it, click Block device (Esc is captured, it does not block)." : "Esc = block.");
            lblStatus.Visible = true;
            btnAllow.Enabled = !arrows && !DisableFailed && !IsDecided;
            btnAllow.Text = arrows ? "Allow (use the arrow keys)" : "Allow";
            if (!arrows)
                lblStatus.Text = storages.Count > 0 ? "Do not open files from this drive until you trust it." : "Only allow it if you just plugged in this device yourself.";
            RefreshSeq();
            RefreshStatus();
        }

        // ------------------------------------------------------------------
        void NewSequence()
        {
            byte[] b = new byte[SeqLen];
            using (var rng = new RNGCryptoServiceProvider()) rng.GetBytes(b);
            for (int i = 0; i < SeqLen; i++) seq[i] = 0x25 + (b[i] % 4); // 256 % 4 == 0 -> unbiased
            pos = 0;
            RefreshSeq();
        }

        void RefreshSeq()
        {
            for (int i = 0; i < SeqLen; i++)
            {
                seqLabels[i].Text = Arrow[seq[i] - 0x25];
                bool done = i < pos;
                seqLabels[i].BackColor = done ? Color.FromArgb(46, 160, 67) : (i == pos ? Color.FromArgb(255, 243, 205) : Color.FromArgb(240, 240, 240));
                seqLabels[i].ForeColor = done ? Color.White : (injectionLock ? Color.Silver : Color.Black);
            }
        }

        void RefreshStatus()
        {
            if (!NeedsArrows || IsDecided) return;
            string s; Color c = Color.DimGray;
            double wait = (cooldownUntil - DateTime.Now).TotalSeconds;
            if (injectionLock) { s = "Arrow-key approval disabled for this connection because automated typing was detected. Block the device (or unplug and re-plug if this was a mistake)."; c = Color.DarkRed; }
            else if (!active) s = "Waiting - another device is being approved first.";
            else if (wait > 0) { s = "Wrong key - a new sequence was generated. Try again in " + Math.Ceiling(wait) + " s."; c = Color.DarkOrange; }
            else s = "Progress: " + pos + " / " + SeqLen + (blockedCount > 0 ? "     Blocked actions: " + blockedCount : "");
            lblStatus.Text = s; lblStatus.ForeColor = c;
        }

        void AppendCaptured(string text)
        {
            blockedCount++;
            captured.Append(text);
            if (txtKeys.TextLength < 20000) txtKeys.AppendText(text);
        }

        /// <summary>Called for every key swallowed while this prompt is the active one.</summary>
        public void OnKey(KeyRecord r)
        {
            if (IsDecided) return;
            bool isArrow = r.Vk >= 0x25 && r.Vk <= 0x28;

            if (r.IsDown && !r.Repeat)
            {
                keyTimes.Add(r.Time);
                if (keyTimes.Count > 12) keyTimes.RemoveAt(0);
                CheckInjection();
            }
            if (r.Text != null && !isArrow) AppendCaptured(r.Injected ? "{inj}" + r.Text : r.Text);
            if (!r.IsDown || r.Repeat || DisableFailed) return;

            // Esc blocks only when no keyboard is pending (e.g. a mouse froze all mouse input, so Block can't be clicked).
            // A pending keyboard could otherwise press Esc itself, close the window and cut off the capture of what it types.
            if (r.Vk == 0x1B && keyboards.Count == 0) { Decide(false); return; }
            if (isArrow) HandleArrow(r);
        }

        /// <summary>Called for mouse actions swallowed while all mouse input is frozen.</summary>
        public void OnMouse(MouseRecord m)
        {
            if (IsDecided) return;
            string s;
            switch (m.Kind)
            {
                case "MOVE": s = "[MOVE " + m.Dist + "px]"; break;
                case "JUMP": s = "[JUMP " + m.Dist + "px to " + m.X + "," + m.Y + "]"; jumps++; break;
                case "WHEEL": s = "[WHEEL]"; break;
                default: s = "[" + m.Kind + " " + m.X + "," + m.Y + "]"; clicks++; break;
            }
            AppendCaptured((m.Injected ? "{inj}" : "") + s);
            if (!mouseWarned && (jumps >= 2 || (jumps >= 1 && clicks >= 1)))
            {
                mouseWarned = true;
                lblInjection.Text = "⚠ AUTOMATED MOUSE ACTIVITY: the cursor jumped directly to screen positions" +
                                    (clicks > 0 ? " and clicked" : "") + ". This is typical of mouse-injection attack devices - block it.";
                lblInjection.Visible = true;
                Guard.Log("Automated mouse activity detected while device pending: " + DevName + " [" + Phys + "]");
            }
        }

        void HandleArrow(KeyRecord r)
        {
            if (r.Injected || injectionLock || !NeedsArrows) return;
            if (DateTime.Now < cooldownUntil) return;

            if (r.Vk == seq[pos])
            {
                pos++;
                RefreshSeq();
                if (pos >= SeqLen) { Decide(true); return; }
            }
            else
            {
                failures++;
                // Brute-force protection: cooldown + fresh random sequence.
                cooldownUntil = DateTime.Now.AddSeconds(failures % 5 == 0 ? 30 : 2);
                NewSequence();
                Guard.Log("Wrong approval sequence for " + DevName + " (failure " + failures + ")");
            }
            RefreshStatus();
        }

        void CheckInjection()
        {
            if (injectionLock || keyTimes.Count < 8) return;
            int n = keyTimes.Count;
            uint span = keyTimes[n - 1] - keyTimes[0];
            double avg = span / (double)(n - 1);
            if (avg >= 30) return;
            injectionLock = true;
            lblInjection.Text = "⚠ AUTOMATED KEYSTROKE INJECTION DETECTED: " + n + " keys at " + avg.ToString("0.0") +
                                " ms/key (humans type ~100+ ms/key). This device is very likely a BadUSB / rubber ducky - block it.";
            lblInjection.Visible = true;
            btnBlock.Focus();
            Guard.Log("Keystroke injection detected from " + DevName + " [" + Phys + "]: avg " + avg.ToString("0.0") + " ms/key");
            RefreshSeq();
            RefreshStatus();
        }

        void Decide(bool allow)
        {
            if (IsDecided) return;
            IsDecided = true;
            timer.Stop();
            btnAllow.Enabled = btnBlock.Enabled = false;
            lblStatus.Visible = true;
            lblStatus.ForeColor = Color.DimGray;
            lblStatus.Text = allow ? "Allowing..." : "Blocking...";
            var h = Decided;
            if (h != null) h(this, allow, rbRemember.Checked ? "1" : rbOnce.Checked ? "O" : "0");
        }
    }
}
