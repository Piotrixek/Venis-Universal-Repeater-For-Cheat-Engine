# ⚡ Veni's Universal Repeater v6.0

**A smart, crash-proof instruction multiplier for Cheat Engine.**

Stop writing manual assembly loops. This Lua extension automates the process of creating "Repeater" cheats (Damage x5, XP x10, etc.) while automatically analyzing memory to prevent game crashes.

![Lua](https://img.shields.io/badge/Lua-Cheat%20Engine-blue) ![Version](https://img.shields.io/badge/Version-3.2-green) ![Author](https://img.shields.io/badge/Made%20By-Veni-red)

## 🔥 Features

* **Universal Compatibility:** Works on both **32-bit** and **64-bit** games automatically.
* **Instant Multipliers:** Turns any instruction (e.g., `add [eax], 10`) into a loop that runs 2x, 5x, or 100x times.
* **Safety Analysis Engine:** The script analyzes the target instruction before hooking. It blocks:
    * Function Prologues (prevents Stack Corruption).
    * Relative Calls/Jumps (prevents breaking offsets).
    * Return instructions.
* **🔍 Smart Tracer:** If you try to hook the start of a function (unsafe), the tool offers to **Trace the Caller**. It listens for what called that function, finds the address, and jumps you there automatically.
* **In-Table UI:** Adds a script to your cheat table with a **Dropdown Menu** to change multiplier values on the fly (Double, Strong, God Mode).
* **Crash Protection:** Uses `pushad/popad` (or x64 equivalent) *inside* the loop to ensure registers remain valid.

## 🚀 Installation & Usage

1.  Open **Cheat Engine**.
2.  Press `Ctrl+L` to open the **Lua Engine**.
3.  Paste the content of lua script.
4.  Click **Execute**.

```lua
addVeniRepeater("ProcessName.exe+12345")
