print([[
------------------------------------------------------------
   VENI'S UNIVERSAL REPEATER v3.2
   Updates:
   - Fixed Label Definition error on small instructions.
   - Fixed DB/JMP collision syntax.
   - Optimized Anti-Spam for Tracer dialog.

   Made by: Veni
   Discord: ._.veni._.
------------------------------------------------------------
]])


if VeniTimer then VeniTimer.destroy() end
VeniTimer = createTimer(nil, false)
VeniTimer.Interval = 300
VeniTimer.OnTimer = function(t)
  local al = getAddressList()
  for i = 0, al.Count - 1 do
    local mr = al.getMemoryRecord(i)
    if mr.Active and string.find(mr.Description, "FIND CALLER") then
       local addrStr = string.match(mr.Description, "%((.*)%)")
       if addrStr then
         local clean = string.gsub(addrStr, '["%+%-]', '')
         local sym = 'found_' .. clean
         local val = readInteger(sym)

         if val and val ~= 0 then
             -- 1. Disable hoe to stop loop/spam
             mr.Active = false

             local hex = string.format('%X', val)
             print(">> SUCCESS! Caller found for " .. addrStr .. ": " .. hex)
             messageDialog("✅ CALLER FOUND! \n\nThe function at " .. addrStr .. "\nwas called by: " .. hex .. "\n\nWe have opened the Disassembler at this location for you.", mtInformation, mbOK)
             getMemoryViewForm().DisassemblerView.SelectedAddress = val
             writeInteger(sym, 0)
         end
       end
    end
  end
end
VeniTimer.Enabled = true


function addVeniRepeater(addr)
  local addrNum = getAddress(addr)
  local is64 = targetIs64Bit()
  local clean = string.gsub(addr, '["%+%-]', '')

  local disasm = disassemble(addrNum)
  local sz = getInstructionSize(addrNum)
  local bytes = readBytes(addrNum, sz, true)
  local opcode = bytes[1]

  --  SCENARIO 1: PROLOGUE DETECTED (Create TRACER!!!!!!)
  if opcode == 0x55 or (opcode == 0x48 and bytes[2] == 0x83 and bytes[3] == 0xEC) then
      local answer = messageDialog("⚠️ UNSAFE HOOK: FUNCTION START ⚠️\n\nYou are trying to hook the start of a function.\nLooping this will crash the game.\n\nWould you like to add a 'TRACER' script instead?\nThis will find what is calling this function so you can hook that instead.", mtError, mbYesNo)

      if answer == mrNo then return end
      local l_found = 'found_' .. clean
      local l_mem = 'trace_' .. clean
      local l_ret = 'ret_' .. clean

      local tot = sz
      while tot < 5 do
         local nxt = getInstructionSize(addrNum + tot)
         tot = tot + nxt
      end

      local raw = readBytes(addrNum, tot, true)
      local bts = ''
      for i, v in ipairs(raw) do bts = bts .. string.format('%02X ', v) end

      local finderCode = ''
      if is64 then
         finderCode = [[
         push rax
         cmp qword ptr []] .. l_found .. [[], 0
         jne @f
         mov rax, [rsp+8]  // 64-bit Return Address
         mov []] .. l_found .. [[], rax
         @@:
         pop rax
         ]]
      else
         finderCode = [[
         push eax
         cmp dword ptr []] .. l_found .. [[], 0
         jne @f
         mov eax, [esp+4]  // 32-bit Return Address
         mov []] .. l_found .. [[], eax
         @@:
         pop eax
         ]]
      end

      local scr = [[
// -----------------------------------------
//   Tool: Veni's Caller Finder
//   Target: ]] .. addr .. [[
//   Author: Veni
//   Discord: ._.veni._.
// -----------------------------------------
[ENABLE]
alloc(]] .. l_mem .. [[, 1024, ]] .. addr .. [[)
label(]] .. l_ret .. [[)
label(]] .. l_found .. [[)
registersymbol(]] .. l_found .. [[)

]] .. l_mem .. [[:
  ]] .. finderCode .. [[

  // Original Code
  db ]] .. bts .. "\n" .. [[
  jmp ]] .. l_ret .. "\n" .. [[

]] .. l_found .. [[:
  dq 0

]] .. addr .. [[:
  jmp ]] .. l_mem .. "\n" .. [[
  ]] .. (tot > 5 and string.rep('nop\n', tot - 5) or '') .. [[
]] .. l_ret .. [[:

[DISABLE]
]] .. addr .. [[:
  db ]] .. bts .. "\n" .. [[

unregistersymbol(]] .. l_found .. [[)
dealloc(]] .. l_mem .. [[)
]]

      local al = getAddressList()
      local mr = al.createMemoryRecord()
      mr.Description = "🔍 FIND CALLER (" .. addr .. ")"
      mr.Type = vtAutoAssembler
      mr.Script = scr
      mr.Color = 0x808000

      local sub = al.createMemoryRecord()
      sub.Description = "Found Address"
      sub.Address = l_found
      sub.ShowAsHex = true
      sub.Type = is64 and vtQword or vtDword
      sub.appendToEntry(mr)

      print("Tracer added for: " .. addr)
      return
  end

  --  SCENARIO 2: UNSAFE RELATIVE (Block)
  if opcode == 0xE8 or opcode == 0xE9 then
      messageDialog("⛔ UNSAFE HOOK: RELATIVE INSTRUCTION ⛔\n\nThis instruction moves based on offset. Hooking it will break the game.\nHook the line BEFORE or AFTER this.", mtError, mbOK)
      return
  end
  if opcode == 0xC3 or opcode == 0xC2 then
      messageDialog("⛔ UNSAFE HOOK: RETURN ⛔", mtError, mbOK)
      return
  end

  --  SCENARIO 3: SAFE INSTRUCTION (Create Repeater)
  local l_mult = 'rept_' .. clean
  local l_mem = 'mem_' .. clean
  local l_ret = 'ret_' .. clean
  local l_loop = 'loop_' .. clean
  local l_counter = 'cnt_' .. clean

  local tot = sz
  while tot < 5 do
     local nxt = getInstructionSize(addrNum + tot)
     tot = tot + nxt
  end
  local raw = readBytes(addrNum, tot, true)
  local bts = ''
  for i, v in ipairs(raw) do bts = bts .. string.format('%02X ', v) end

  local save = is64 and 'pushfq\npush rax\npush rbx\npush rcx\npush rdx\npush rsi\npush rdi\npush rbp\npush r8\npush r9\npush r10\npush r11\npush r12\npush r13\npush r14\npush r15' or 'pushad\npushfd'
  local rest = is64 and 'pop r15\npop r14\npop r13\npop r12\npop r11\npop r10\npop r9\npop r8\npop rbp\npop rdi\npop rsi\npop rdx\npop rcx\npop rbx\npop rax\npopfq' or 'popfd\npopad'

  local scr = [[
// -----------------------------------------
//   Tool: Veni's Universal Repeater
//   Target: ]] .. disasm .. [[
//   Author: Veni
//   Discord: ._.veni._.
// -----------------------------------------
[ENABLE]
alloc(]] .. l_mem .. [[, 1024, ]] .. addr .. [[)
label(]] .. l_ret .. [[)
label(]] .. l_loop .. [[)
label(]] .. l_mult .. [[)
label(]] .. l_counter .. [[)
registersymbol(]] .. l_mult .. [[)

]] .. l_mem .. [[:
  push eax
  mov eax, []] .. l_mult .. [[]
  mov []] .. l_counter .. [[], eax
  pop eax

]] .. l_loop .. [[:
  ]] .. save .. "\n" .. [[
  db ]] .. bts .. "\n" .. [[
  ]] .. rest .. "\n" .. [[
  dec []] .. l_counter .. [[]
  jnz ]] .. l_loop .. "\n" .. [[
  jmp ]] .. l_ret .. "\n" .. [[

]] .. l_mult .. [[:
  dd #5
]] .. l_counter .. [[:
  dd 0

]] .. addr .. [[:
  jmp ]] .. l_mem .. "\n" .. [[
  ]] .. (tot > 5 and string.rep('nop\n', tot - 5) or '') .. [[
]] .. l_ret .. [[:

[DISABLE]
]] .. addr .. [[:
  db ]] .. bts .. "\n" .. [[

unregistersymbol(]] .. l_mult .. [[)
dealloc(]] .. l_mem .. [[)
]]

  local al = getAddressList()
  local mr = al.createMemoryRecord()
  mr.Description = "Veni's Repeater: " .. disasm
  mr.Type = vtAutoAssembler
  mr.Script = scr
  mr.Color = 0xFF0000

  local sub = al.createMemoryRecord()
  sub.Description = "Set Repeats (Made by Veni)"
  sub.Address = l_mult
  sub.Type = vtDword
  sub.appendToEntry(mr)

  local dl = sub.DropDownList
  dl.Text = "2:Double\n5:Strong\n10:Overkill\n100:God Mode"
  sub.DropDownReadOnly = false
  sub.DropDownDescriptionOnly = false
  sub.DisplayAsDropDownListItem = true

  print("Repeater hook added for: " .. addr)
end

-- Hook your target wot u want
-- addVeniRepeater('"Tutorial-i386.exe"+26A90')
addVeniRepeater('"Tutorial-i386.exe"+8ECA2')