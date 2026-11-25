# Generates assets\DragonGuard.ico (exe/tray/window icon) and assets\logo.png (approval window header) from logo.jpg.
# Run once after changing logo.jpg:  powershell -ExecutionPolicy Bypass -File tools\make-assets.ps1
param([string]$Root = (Split-Path -Parent $PSScriptRoot))

Add-Type -ReferencedAssemblies System.Drawing -TypeDefinition @'
using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.IO;

public static class LogoAssets
{
    static Bitmap Resize(Bitmap src, Rectangle crop, int w, int h)
    {
        var b = new Bitmap(w, h, PixelFormat.Format32bppArgb);
        using (var g = Graphics.FromImage(b))
        {
            g.InterpolationMode = InterpolationMode.HighQualityBicubic;
            g.PixelOffsetMode = PixelOffsetMode.HighQuality;
            g.SmoothingMode = SmoothingMode.HighQuality;
            g.Clear(Color.Transparent);
            g.DrawImage(src, new Rectangle(0, 0, w, h), crop, GraphicsUnit.Pixel);
        }
        return b;
    }

    /// <summary>Emblem: opaque white disc inside the ring, outside it only the dark strokes (horns) remain.</summary>
    static Bitmap Emblem(Bitmap src, int cx, int cy, int half, int discR)
    {
        int size = half * 2;
        var b = new Bitmap(size, size, PixelFormat.Format32bppArgb);
        for (int y = 0; y < size; y++)
            for (int x = 0; x < size; x++)
            {
                Color c = src.GetPixel(cx - half + x, cy - half + y);
                double dist = Math.Sqrt((x - half) * (double)(x - half) + (y - half) * (double)(y - half));
                double disc = Math.Max(0, Math.Min(1, discR - dist + 0.5));
                int minc = Math.Min(c.R, Math.Min(c.G, c.B));
                double ink = Math.Max(0, Math.Min(1, (240 - minc) / 90.0));
                double a = Math.Max(disc, ink);
                int r = c.R, g = c.G, bl = c.B;
                if (disc < 1 && ink > 0)
                {   // un-blend from the white background so edges stay crisp on dark taskbars
                    r = Clamp(255 - (255 - c.R) / ink); g = Clamp(255 - (255 - c.G) / ink); bl = Clamp(255 - (255 - c.B) / ink);
                }
                b.SetPixel(x, y, Color.FromArgb(Clamp(a * 255), r, g, bl));
            }
        return b;
    }

    static byte[] Png(Bitmap b)
    {
        using (var ms = new MemoryStream()) { b.Save(ms, ImageFormat.Png); return ms.ToArray(); }
    }

    /// <summary>Classic 32-bit icon image (BITMAPINFOHEADER + BGRA bottom-up + AND mask); System.Drawing.Icon can't read small PNG entries.</summary>
    static byte[] Dib(Bitmap b)
    {
        int w = b.Width, h = b.Height, maskRow = ((w + 31) / 32) * 4;
        using (var ms = new MemoryStream())
        using (var wr = new BinaryWriter(ms))
        {
            wr.Write(40); wr.Write(w); wr.Write(h * 2); wr.Write((short)1); wr.Write((short)32);
            wr.Write(0); wr.Write(w * h * 4 + maskRow * h); wr.Write(0); wr.Write(0); wr.Write(0); wr.Write(0);
            for (int y = h - 1; y >= 0; y--)
                for (int x = 0; x < w; x++) { Color c = b.GetPixel(x, y); wr.Write(c.B); wr.Write(c.G); wr.Write(c.R); wr.Write(c.A); }
            for (int y = h - 1; y >= 0; y--)
            {
                var row = new byte[maskRow];
                for (int x = 0; x < w; x++) if (b.GetPixel(x, y).A == 0) row[x / 8] |= (byte)(0x80 >> (x % 8));
                wr.Write(row);
            }
            return ms.ToArray();
        }
    }

    static int Clamp(double v) { return v < 0 ? 0 : v > 255 ? 255 : (int)Math.Round(v); }

    public static void Make(string jpg, string icoPath, string pngPath)
    {
        using (var src = new Bitmap(jpg))
        {
            double k = src.Width / 2048.0;
            // ---- icon ----
            using (var em = Emblem(src, (int)(1023 * k), (int)(956 * k), (int)(590 * k), (int)(548 * k)))
            {
                int[] sizes = { 256, 64, 48, 40, 32, 24, 20, 16 };
                var pngs = new byte[sizes.Length][];
                for (int i = 0; i < sizes.Length; i++)
                    using (var r = Resize(em, new Rectangle(0, 0, em.Width, em.Height), sizes[i], sizes[i]))
                    pngs[i] = sizes[i] >= 256 ? Png(r) : Dib(r);
                using (var fs = File.Create(icoPath))
                using (var w = new BinaryWriter(fs))
                {
                    w.Write((short)0); w.Write((short)1); w.Write((short)sizes.Length);
                    int offset = 6 + 16 * sizes.Length;
                    for (int i = 0; i < sizes.Length; i++)
                    {
                        w.Write((byte)(sizes[i] >= 256 ? 0 : sizes[i])); w.Write((byte)(sizes[i] >= 256 ? 0 : sizes[i]));
                        w.Write((byte)0); w.Write((byte)0); w.Write((short)1); w.Write((short)32);
                        w.Write(pngs[i].Length); w.Write(offset);
                        offset += pngs[i].Length;
                    }
                    foreach (var p in pngs) w.Write(p);
                }
            }
            // ---- header logo (emblem + "DRAGON DATA"), white background ----
            var crop = new Rectangle((int)(370 * k), (int)(360 * k), (int)(1310 * k), (int)(1340 * k));
            int h = 220, wpx = (int)Math.Round(h * crop.Width / (double)crop.Height);
            using (var r = Resize(src, crop, wpx, h)) r.Save(pngPath, ImageFormat.Png);
        }
    }
}
'@

$assets = Join-Path $Root 'assets'
New-Item -ItemType Directory -Force $assets | Out-Null
[LogoAssets]::Make((Join-Path $Root 'logo.jpg'), (Join-Path $assets 'DragonGuard.ico'), (Join-Path $assets 'logo.png'))
Write-Host "Wrote $assets\DragonGuard.ico and $assets\logo.png"
