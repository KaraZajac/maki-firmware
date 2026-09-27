//! Icons: a 64x64 PNG or PBM, as it should look on maki (light shapes on dark, usually), into
//! the words bundles carry, and back for `inspect`.

use std::path::Path;

use maki_bundle::ICON_WORDS;

const SIZE: usize = 64;

/// Light pixels, row by row.
fn pixels(path: &Path) -> Result<Vec<bool>, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if bytes.starts_with(b"\x89PNG") {
        let mut decoder = png::Decoder::new(std::io::Cursor::new(&bytes));
        decoder.set_transformations(png::Transformations::normalize_to_color8());
        let mut reader = decoder.read_info().map_err(|e| format!("{}: {e}", path.display()))?;
        let mut buf = vec![0; reader.output_buffer_size().ok_or("PNG too big")?];
        let info = reader.next_frame(&mut buf).map_err(|e| format!("{}: {e}", path.display()))?;
        if (info.width, info.height) != (SIZE as u32, SIZE as u32) {
            return Err(format!("{}: {}x{}, not 64x64", path.display(), info.width, info.height));
        }
        let channels = info.color_type.samples();
        let row = info.line_size;
        let mut out = Vec::with_capacity(SIZE * SIZE);
        for y in 0..SIZE {
            for x in 0..SIZE {
                let p = &buf[y * row + x * channels..][..channels];
                let (lum, alpha) = match channels {
                    1 => (p[0] as u32, 255),
                    2 => (p[0] as u32, p[1] as u32),
                    3 => ((p[0] as u32 * 3 + p[1] as u32 * 6 + p[2] as u32) / 10, 255),
                    _ => ((p[0] as u32 * 3 + p[1] as u32 * 6 + p[2] as u32) / 10, p[3] as u32),
                };
                out.push(lum * alpha / 255 >= 128);
            }
        }
        Ok(out)
    } else if bytes.starts_with(b"P1") {
        // plain PBM: 1 is black
        let text = String::from_utf8_lossy(&bytes);
        let mut tokens = text
            .lines()
            .map(|l| l.split('#').next().unwrap_or(""))
            .flat_map(|l| l.split_whitespace().map(String::from).collect::<Vec<_>>())
            .skip(1);
        let w: usize = tokens.next().and_then(|t| t.parse().ok()).ok_or("PBM: no width")?;
        let h: usize = tokens.next().and_then(|t| t.parse().ok()).ok_or("PBM: no height")?;
        if (w, h) != (SIZE, SIZE) {
            return Err(format!("{}: {w}x{h}, not 64x64", path.display()));
        }
        let bits: String = tokens.collect();
        if bits.len() != SIZE * SIZE {
            return Err(format!("{}: {} pixels, not {}", path.display(), bits.len(), SIZE * SIZE));
        }
        Ok(bits.chars().map(|c| c == '0').collect())
    } else {
        Err(format!("{}: not a PNG or plain PBM (P1)", path.display()))
    }
}

/// `maki_icons` form: 64 rows of two words, pixel x in bit x % 32 of word x / 32, a set bit dark.
pub fn load(path: &Path) -> Result<[u32; ICON_WORDS], String> {
    let light = pixels(path)?;
    let mut words = [0u32; ICON_WORDS];
    for y in 0..SIZE {
        for x in 0..SIZE {
            if !light[y * SIZE + x] {
                words[y * 2 + x / 32] |= 1 << (x % 32);
            }
        }
    }
    Ok(words)
}

/// For the terminal: two rows a line.
pub fn render(words: &[u32; ICON_WORDS]) -> String {
    let lit = |x: usize, y: usize| words[y * 2 + x / 32] & (1 << (x % 32)) == 0;
    let mut s = String::new();
    for y in (0..SIZE).step_by(2) {
        for x in 0..SIZE {
            s.push(match (lit(x, y), lit(x, y + 1)) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            });
        }
        s.push('\n');
    }
    s
}
