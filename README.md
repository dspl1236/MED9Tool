# MED9Tool

Open-source editor for MPC5xx-based Bosch MED9 ECUs (MED9.1, MED9.5).

Part of the VAG ECU tooling suite alongside [TriCoreTool](https://github.com/dspl1236/TriCoreTool) (MED17/EDC17), [MESevenTool](https://github.com/dspl1236/MESevenTool) (ME7.x), and [DigiTool](https://github.com/dspl1236/DigiTool) (Digifant).

## Platform

MED9 = **M**otronic **E**lectronic **D**irect injection, generation **9**. These are Bosch GDI (gasoline direct injection) ECUs using Freescale/NXP MPC5xx PowerPC processors. They sit between the older ME7 (port injection) and the newer MED17 (TriCore) generations.

## Supported ECU Families

| PN Family | ECU Variant | Processor | Engine | Vehicle | Files |
|-----------|-------------|-----------|--------|---------|-------|
| 03H906032 | MED9.1 | MPC5567 | 3.6 VR6 FSI | Porsche Cayenne / VW Touareg | 54 SGO |
| 03H906026 | MED9.1 | MPC5567 | 3.6 VR6 FSI | Cayenne / Touareg (older) | 84 FRF (AES) |
| 03H997033 | MED9.1 | MPC5567 | 3.6 VR6 FSI | Cayenne (reman) | 9 SGO |
| 03H997034 | MED9.1 | MPC5567 | 3.6 VR6 FSI | Cayenne (reman) | 9 SGO |
| 1K0907115S | MED9.1 | MPC5567 | 2.0T FSI | Golf V / Jetta (early) | 1 SGO |

**Total: 157 files identified**

## Why Not TriCoreTool?

TriCoreTool requires Infineon TriCore processors (TC1766/TC1793/TC1797). MED9 uses Freescale MPC5xx PowerPC — completely different instruction set, memory map, and calibration structure. Same Bosch engineering philosophy, different silicon.

## Status

Early stage — file inventory and ROM identification. Scanner and patch support pending.

## License

MIT
