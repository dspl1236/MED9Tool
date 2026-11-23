# Third-Party Notices

MED9Tool is MIT-licensed. It includes code derived from the project below.

## lsdlsd88/TCU-FRF-SGO-UNPACKER (MIT)

The keyed record-stream decoder in `med9tool/sgo_unpack.py` — `record_decode`
and its `_xor_span` helper (XOR-FF, a `1A 01` sync, repeating-key XOR, and
big-endian 16-bit literal/RLE records terminated by a 24-bit checksum field) —
is a faithful port of `sgo_legacy.py` from:

> <https://github.com/lsdlsd88/TCU-FRF-SGO-UNPACKER>

That project is MIT-licensed and is itself verified against the original
`SGO Extract.exe` (2013). The MED9 descramble key `CodeRobert` (and the
fallbacks `GEHEIM` / `BiWbBuD101` / `Mst2Bosch`) are interoperability material
published in that project — SGO container decode keys only, not immobiliser,
component-protection, or signature material.

```
MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
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
SOFTWARE.
```
