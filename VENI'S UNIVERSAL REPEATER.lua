print([[
------------------------------------------------------------
   VENI'S UNIVERSAL REPEATER v6.0 (Stable)
   Updates:
   - Kept 40+53 Prologue detection.
   - Kept Relative Call auto-fixer.

   Made by: Veni
   Discord: ._.veni._.
------------------------------------------------------------
]])


if VeniTimer then VeniTimer.destroy() end
VeniTimer = createTimer(nil, false)
VeniTimer.Interval = 200
VeniTimer.OnTimer = function(t)
  local al = getAddressList()
  for i = 0, al.Count - 1 do
    local mr = al.getMemoryRecord(i)
    if mr.Active and string.find(mr.Description, "FIND CALLER") then
       local addrStr = string.match(mr.Description, "%((.*)%)")
       if addrStr then
         local clean = string.gsub(addrStr, '["%+%-]', '')
         local sym = 'found_' .. clean

         local val = readPointer(sym)

         if val and val > 0 then
             mr.Active = false
             local hex = string.format('%X', val)
             print(">> SUCCESS! Caller found for " .. addrStr .. ": " .. hex)
             messageDialog("✅ CALLER FOUND! \n\nThe function at " .. addrStr .. "\nwas called by: " .. hex .. "\n\nOpening Disassembler...", mtInformation, mbOK)
             getMemoryViewForm().DisassemblerView.SelectedAddress = val
             writeQword(sym, 0)
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

  --  SCENARIO 1: PROLOGUE DETECTED
  local isPrologue = false
  -- Standard PUSH
  if opcode >= 0x50 and opcode <= 0x57 then isPrologue = true end
  -- Extended PUSH (41 50-57)
  if opcode == 0x41 and (bytes[2] >= 0x50 and bytes[2] <= 0x57) then isPrologue = true end
  -- REX PUSH (40-4F 50-57)
  if opcode >= 0x40 and opcode <= 0x4F and (bytes[2] >= 0x50 and bytes[2] <= 0x57) then isPrologue = true end
  -- SUB RSP
  if opcode == 0x48 and (bytes[2] == 0x83 or bytes[2] == 0x81) and bytes[3] == 0xEC then isPrologue = true end

  if isPrologue then
      local answer = messageDialog("⚠️ UNSAFE HOOK: FUNCTION START ⚠️\n\nTarget: " .. disasm .. "\n\nThis instruction modifies the Stack Pointer.\nLooping it will crash the game.\n\nUse TRACER to find the caller?", mtError, mbYesNo)

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

      -- x64: Return address is at [rsp]. We push rax (8 bytes). So it is at [rsp+8].
      local finderCode = ''
      if is64 then
         finderCode = [[
         push rax
         cmp qword ptr []] .. l_found .. [[], 0
         jne @f
         mov rax, [rsp+8]   // Grab Return Address
         mov []] .. l_found .. [[], rax
         @@:
         pop rax
         ]]
      else
         finderCode = [[
         push eax
         cmp dword ptr []] .. l_found .. [[], 0
         jne @f
         mov eax, [esp+4]   // Grab Return Address
         mov []] .. l_found .. [[], eax
         @@:
         pop eax
         ]]
      end

      local scr = [[
// -----------------------------------------
//   Tool: Veni's Caller Finder (v6.0)
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

  --  SCENARIO 2: RELATIVE CALL/JUMP (Auto-Fixer)
  local instructionToRun = ""
  local note = ""

  if opcode == 0xE8 or opcode == 0xE9 then
      local offset = readInteger(addrNum + 1, true)
      local targetAddr = addrNum + 5 + offset
      local targetHex = string.format('%X', targetAddr)
      note = "// FIXED RELATIVE: Pointing to " .. targetHex

      if opcode == 0xE8 then
         if is64 then
            instructionToRun = "mov rax, " .. targetHex .. "\n  call rax"
         else
            instructionToRun = "call " .. targetHex
         end
      else
         if is64 then
            instructionToRun = "mov rax, " .. targetHex .. "\n  jmp rax"
         else
            instructionToRun = "jmp " .. targetHex
         end
      end
  elseif opcode == 0xC3 or opcode == 0xC2 then
      messageDialog("⛔ UNSAFE HOOK: RETURN ⛔", mtError, mbOK)
      return
  else
      local bts = ''
      for i, v in ipairs(bytes) do bts = bts .. string.format('%02X ', v) end
      instructionToRun = "db " .. bts
  end

  --  SCENARIO 3: CODE GENERATION (Repeater)
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
  local rawOriginal = readBytes(addrNum, tot, true)
  local btsOriginal = ''
  for i, v in ipairs(rawOriginal) do btsOriginal = btsOriginal .. string.format('%02X ', v) end

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

  ]] .. note .. "\n" .. [[
  ]] .. instructionToRun .. "\n" .. [[

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
  db ]] .. btsOriginal .. "\n" .. [[

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

addVeniRepeater('"Tutorial-i386.exe"+8ECA2')
