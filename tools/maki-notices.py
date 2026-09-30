#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Part of maki (see NOTICE.md): Copyright (c) 2026 .leviathan
"""Third-party notices for what maki ships: the badge image, and the maki store's apps.

    tools/maki-notices.py image   > THIRD-PARTY-NOTICES.md
    tools/maki-notices.py sdk     > sdk/THIRD-PARTY-NOTICES.md

Asks cargo which crates are compiled in (the loader, the kernel and each service, with the
features `cargo xtask baosec-lite` builds them with; or each app in sdk/, for WebAssembly and,
for native ones, the badge), then writes each crate's license and its authors' own notices: its
LICENSE files, its NOTICE if it has one. Where a crate offers a choice of licenses, the notice is
for the first of PREFERRED it offers. Identical texts are written once, naming every crate they
cover. Build scripts and procedural macros aren't in the binaries, so they aren't listed.
"""

import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# what `cargo xtask baosec-lite maki-launcher~flash maki-keys vault2 maki-link maki-apps maki-app-host` builds
IMAGE = [
    ('riscv32imac-unknown-xous-elf',
     ['xous-swapper', 'keystore', 'xous-ticktimer', 'xous-log', 'xous-names', 'usb-bao1x', 'bao1x-hal-service',
      'modals', 'pddb', 'bao-video', 'maki-launcher', 'maki-keys', 'vault2', 'maki-link', 'maki-apps', 'maki-app-host'],
     ['timestamp', 'board-baosec', 'swap', 'oem-baosec-lite', 'bao1x', 'utralib/bao1x'], False),
    ('riscv32imac-unknown-none-elf', ['loader'],
     ['board-baosec', 'swap', 'debug-print', 'oem-baosec-lite', 'bao1x', 'utralib/bao1x'], True),
    ('riscv32imac-unknown-none-elf', ['xous-kernel'],
     ['board-baosec', 'print-panics', 'swap', 'v2p', 'bao1x', 'utralib/bao1x'], False),
]

# a choice of licenses: the first of these that's offered
PREFERRED = ['MIT', 'Apache-2.0', 'BSD-3-Clause', 'BSD-2-Clause', 'ISC', 'Zlib', 'BSL-1.0', 'Unicode-3.0',
             'Unicode-DFS-2016', 'CC0-1.0', 'Unlicense', '0BSD', 'MIT-0', 'BSD-1-Clause', 'LLVM-exception']

# licenses that ask for nothing to be passed on
NO_NOTICE = {'CC0-1.0', 'Unlicense', '0BSD', 'MIT-0'}


def run(cmd, cwd):
    return subprocess.run(cmd, cwd=cwd, check=True, capture_output=True, text=True).stdout


def compiled_in(mode):
    """(name, version, source) of every package compiled into what's shipped."""
    out = set()
    if mode == 'image':
        groups = [(ROOT, *g) for g in IMAGE]
    else:
        sdk = ROOT / 'sdk'
        members = json.loads(run(['cargo', 'metadata', '--format-version', '1', '--no-deps'], sdk))['packages']
        apps = [p['name'] for p in members if p['name'] != 'maki']
        native = [p['name'] for p in members
                  if (Path(p['manifest_path']).parent / 'maki.toml').exists()
                  and 'kind = "native"' in (Path(p['manifest_path']).parent / 'maki.toml').read_text()]
        groups = [(sdk, 'wasm32-unknown-unknown', apps, [], False),
                  (sdk, 'riscv32imac-unknown-xous-elf', native, [], False)]
    for cwd, target, packages, features, no_default in groups:
        if not packages:
            continue
        cmd = ['cargo', 'tree', '--target', target, '-e', 'normal,no-proc-macro', '--prefix', 'none', '--format', '{p}']
        for p in packages:
            cmd += ['-p', p]
        for f in features:
            cmd += ['--features', f]
        if no_default:
            cmd.append('--no-default-features')
        for line in run(cmd, cwd).splitlines():
            m = re.match(r'^(\S+) v(\S+)(?: \((.*?)\))?(?: \(\*\))?$', line.strip())
            if m:
                where = m.group(3) or ''
                out.add((m.group(1), m.group(2), '' if where == '*' else where))  # (*): shown before
    return out


def metadata(cwd):
    """Every package cargo knows of there."""
    return json.loads(run(['cargo', 'metadata', '--format-version', '1'], cwd))['packages']


def resolve(packages, name, version, where):
    """The package cargo tree named: a folder, a git repository, or crates.io."""
    for p in packages:
        if p['name'] != name or p['version'] != version:
            continue
        source = p.get('source') or ''
        if where.startswith('/'):
            if Path(p['manifest_path']).parent == Path(where):
                return p
        elif where:
            if source.startswith('git+') and source[4:].split('?')[0].split('#')[0] == where.split('?')[0].split('#')[0]:
                return p
        elif source.startswith('registry+'):
            return p
    return None


XOUS_AUTHORS = re.compile(r'xobs|bunnie|Sean Cross|kosagi|baochip|Sam Blenny|gsora', re.I)


def own_notice(p):
    """A crate of this repository that's someone else's code, with a license of its own."""
    here = Path(p['manifest_path']).parent
    if here == ROOT or re.search(r'maki|roughtime', p['name']):
        return False
    xous = (ROOT / 'LICENSE').read_text()
    files = [f for f in here.iterdir() if re.match(r'^(LICEN[CS]E|COPYING|NOTICE)', f.name, re.I)]
    own_files = [f for f in files if f.read_text(errors='replace') != xous]
    outside = any(not XOUS_AUTHORS.search(a) for a in p.get('authors') or [])
    return bool(own_files) or (bool(p.get('license')) and outside)


def spdx_choice(expr):
    """The licenses a notice is needed for: one from each OR, every one of an AND."""
    expr = (expr or '').replace('/', ' OR ')
    parts = [p.strip() for p in re.split(r'\bAND\b', expr.replace('(', '').replace(')', '')) if p.strip()]
    chosen = []
    for part in parts:
        options = [o.strip() for o in re.split(r'\bOR\b', part) if o.strip()]
        options = [re.sub(r'\s+WITH\s+.*$', '', o) for o in options]
        best = next((p for p in PREFERRED if p in options), options[0] if options else None)
        if best and best not in chosen:
            chosen.append(best)
    return chosen


def kind_of(text):
    t = text[:4000]
    if 'Apache License' in t and 'Version 2.0' in t:
        return 'Apache-2.0'
    if 'Permission is hereby granted, free of charge' in t:
        return 'MIT'
    if 'Redistribution and use in source and binary forms' in t:
        return 'BSD-3-Clause' if 'Neither the name' in t or 'endorse or promote' in t else 'BSD-2-Clause'
    if 'Permission to use, copy, modify, and/or distribute' in t or 'Permission to use, copy, modify, and distribute' in t:
        return 'ISC'
    if "This software is provided 'as-is'" in t:
        return 'Zlib'
    if 'This is free and unencumbered software' in t:
        return 'Unlicense'
    if 'Boost Software License' in t:
        return 'BSL-1.0'
    if 'CERN' in t and 'Open Hardware' in t:
        return 'CERN-OHL'
    if 'UNICODE' in t.upper() and 'LICENSE' in t.upper():
        return 'Unicode'
    if 'CC0' in t or 'Creative Commons Legal Code' in t:
        return 'CC0-1.0'
    return None


def license_files(pkg):
    """The crate's license and notice files: in its folder, or the repository's it came from."""
    here = Path(pkg['manifest_path']).parent
    dirs = [here]
    # a crate in a git checkout, or in a workspace: its repository's files count too
    for up in here.parents:
        if (up / '.git').exists() or up.name in ('checkouts',) or len(dirs) > 3:
            break
        dirs.append(up)
    found = []
    for d in dirs:
        for f in sorted(d.iterdir()) if d.is_dir() else []:
            if f.is_file() and re.match(r'^(LICEN[CS]E|COPYING|NOTICE|UNLICENSE|COPYRIGHT)', f.name, re.I):
                found.append(f)
        if found:
            break
    return found


def texts_for(pkg, chosen):
    """The texts to write for this crate: its own files for the licenses chosen, and its NOTICE."""
    files = license_files(pkg)
    out = []
    by_kind = {}
    for f in files:
        try:
            text = f.read_text(errors='replace').strip()
        except OSError:
            continue
        if f.name.upper().startswith('NOTICE'):
            out.append(('NOTICE', text))
            continue
        k = kind_of(text)
        by_kind.setdefault(k, text)
    if chosen == ['(none declared)']:
        # no license in its Cargo.toml: its files say, the first of PREFERRED among them
        found = [k for k in PREFERRED if k in by_kind] or [k for k in by_kind if k]
        chosen = found[:1] or chosen
    for lic in chosen:
        if lic in NO_NOTICE:
            continue
        text = by_kind.get(lic)
        if text is None and len(by_kind) == 1 and len(chosen) == 1:
            text = next(iter(by_kind.values()))  # one file, one license: that's it
        if text is None:
            text = standard(lic, pkg)
        elif kind_of(text) == 'Apache-2.0':
            # the license once, at the end; what's the crate's own is its copyright lines
            mine = [l.strip() for l in text.splitlines() if re.match(r'\s*Copyright', l) and '[yyyy]' not in l]
            authors = ', '.join(re.sub(r'\s*<[^>]*>', '', a) for a in pkg.get('authors') or [])
            text = ('Licensed under the Apache License 2.0, whose text is at the end of this file.\n'
                    + ('\n'.join(mine) + '\n' if mine else '') + (f'Authors: {authors}' if authors else '')).strip()
        out.append((kind_of(text) if lic == '(none declared)' else lic, text))
    return out


MIT = '''Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.'''

ISC = '''Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.'''

BSD3 = '''Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.'''

ZLIB = '''This software is provided 'as-is', without any express or implied
warranty. In no event will the authors be held liable for any damages
arising from the use of this software.

Permission is granted to anyone to use this software for any purpose,
including commercial applications, and to alter it and redistribute it
freely, subject to the following restrictions:

1. The origin of this software must not be misrepresented; you must not
   claim that you wrote the original software. If you use this software
   in a product, an acknowledgment in the product documentation would be
   appreciated but is not required.
2. Altered source versions must be plainly marked as such, and must not be
   misrepresented as being the original software.
3. This notice may not be removed or altered from any source distribution.'''


def standard(lic, pkg):
    """A crate that names a license but doesn't ship its text: the text, with its authors."""
    authors = ', '.join(re.sub(r'\s*<[^>]*>', '', a) for a in pkg.get('authors') or []) or f"the {pkg['name']} authors"
    body = {'MIT': MIT, 'ISC': ISC, 'BSD-3-Clause': BSD3, 'Zlib': ZLIB}.get(lic)
    if lic == 'Apache-2.0':
        # no license file: its copyright is in its source's headers, if anywhere
        here = Path(pkg['manifest_path']).parent
        heads = []
        for f in ('src/lib.rs', 'src/main.rs'):
            if (here / f).exists():
                heads = [re.sub(r'^Copyright(?=\d)', 'Copyright ', re.sub(r'^\s*//\s*', '', l).strip()) for l in (here / f).read_text(errors='replace').splitlines()[:20]
                         if re.match(r'^\s*//\s*Copyright', l)]
                break
        return ('Licensed under the Apache License 2.0, whose text is at the end of this file.\n'
                + ''.join(h + '\n' for h in heads) + f'Authors: {authors}')
    if body is None:
        return f"Licensed under {lic}; its text: https://spdx.org/licenses/{lic}.html"
    return f"{'MIT License' if lic == 'MIT' else lic}\n\nCopyright (c) {authors}\n\n{body}"


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else 'image'
    if mode not in ('image', 'sdk'):
        sys.exit(__doc__)
    shipped = compiled_in(mode)
    meta = metadata(ROOT if mode == 'image' else ROOT / 'sdk')
    commit = run(['git', 'rev-parse', '--short=9', 'HEAD'], ROOT).strip()

    third, vendored, missing = [], [], []
    for name, version, where in shipped:
        pkg = resolve(meta, name, version, where)
        if pkg is None:
            missing.append(f'{name} {version} {where}')
        elif pkg.get('source'):
            third.append(pkg)
        elif own_notice(pkg):
            vendored.append(pkg)
    if missing:
        sys.exit('cargo metadata has no package for: ' + ', '.join(missing))
    listed = sorted({p['id']: p for p in third + vendored}.values(), key=lambda p: (p['name'].lower(), p['version']))

    groups = {}   # text -> crates it covers
    rows = []
    for p in listed:
        chosen = spdx_choice(p.get('license')) or ['(none declared)']
        where = p.get('repository') or (p.get('source') or '').split('+', 1)[-1] or 'this repository'
        if not p.get('source'):
            where = f"this repository: {os.path.relpath(Path(p['manifest_path']).parent, ROOT)}"
        rows.append(f"| {p['name']} | {p['version']} | {p.get('license') or 'none declared'} | {where} |")
        for lic, text in texts_for(p, chosen):
            key = hashlib.sha256(text.encode()).hexdigest()
            groups.setdefault(key, [lic, text, []])[2].append(f"{p['name']} {p['version']}")

    what = ('the badge image: `loader.uf2`, `xous.uf2` and `swap.uf2` (the loader, the kernel and '
            'every service)' if mode == 'image' else "the maki store's apps, built from `sdk/`")
    print(f"# Third-party notices\n")
    print(f"For {what}, from maki-firmware at `{commit}`. Made by `tools/maki-notices.py {mode}`.\n")
    print("Xous is licensed under the Apache License 2.0 (`LICENSE`), maki's own code under the MIT "
          "License (`LICENSES/MIT.txt`): see `NOTICE.md`. What follows is everything else compiled in, "
          "with its license and its authors' notices. Where a crate offers a choice of licenses, the "
          "notice is for the one taken here (MIT, where offered). None is under a copyleft license.\n")
    if mode == 'image':
        print("The image also carries glyphs from Unifont (SIL Open Font License 1.1) and data from "
              "the Unicode Consortium: their notices are at the end.\n")
    print(f"## {len(listed)} components\n")
    print("| Crate | Version | License | Source |\n|---|---|---|---|")
    print('\n'.join(rows))
    print("\n## Their notices\n")
    for lic, text, crates in sorted(groups.values(), key=lambda g: (g[0], g[2][0].lower())):
        print(f"### {lic}: {', '.join(sorted(crates, key=str.lower))}\n")
        print("```\n" + text.replace('```', "'''") + "\n```\n")
    if mode == 'image':
        legal = (ROOT / 'libs' / 'blitstr2' / 'LEGAL.md').read_text()
        print("## Glyphs and Unicode data (libs/blitstr2, LEGAL.md)\n")
        print(re.sub(r'^#', '###', legal, flags=re.M))
    print("\n## Apache License 2.0\n\nThe text of the Apache License, which Xous and the crates above "
          "under it are licensed under:\n")
    print("```\n" + (ROOT / 'LICENSE').read_text().strip() + "\n```")


if __name__ == '__main__':
    main()
