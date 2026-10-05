--- TN5250 emulation library for Nmap NSE.
--
-- Connects to an IBM i (AS/400, iSeries) telnet server, performs the
-- RFC 1205 / RFC 2877 TN5250 negotiation, reads the 5250 data stream and
-- renders the display into a text screen plus a table of input fields
-- (including hidden / non-display fields such as password entries).
--
-- The design deliberately mirrors Nmap's bundled <code>tn3270.lua</code>
-- (by Philip Young / Soldier of Fortran): a small Telnet object exposes
-- <code>initiate</code>, <code>get_screen</code>, <code>any_hidden</code>,
-- <code>hidden_fields</code> and buffer-address helpers so a thin NSE
-- script can drive it the same way <code>tn3270-screen.nse</code> drives
-- the 3270 library. EBCDIC (code page 037) conversion is reused from
-- Nmap's <code>drda.lua</code>, exactly as the 3270 library does.
--
-- Protocol references:
--   * RFC 1205 - 5250 Telnet Interface
--   * RFC 2877 - 5250 Telnet Enhancements
--   * IBM 5250 Functions Reference (SA21-9247)
--   * The open-source tn5250 project (https://github.com/tn5250/tn5250)
--
-- @author Ayden <butera.ayden@gmail.com>
-- @copyright Same as Nmap -- see https://nmap.org/book/man-legal.html

local comm   = require "comm"
local drda   = require "drda"   -- reused only for EBCDIC <-> ASCII tables
local stdnse = require "stdnse"
local string = require "string"
local table  = require "table"

_ENV = stdnse.module("tn5250", stdnse.seeall)

-- Telnet protocol bytes (RFC 854) ------------------------------------------
local IAC   = 0xff
local DONT  = 0xfe
local DO    = 0xfd
local WONT  = 0xfc
local WILL  = 0xfb
local SB    = 0xfa
local SE    = 0xf0
local EOR   = 0xef        -- End Of Record (used after IAC)

-- Telnet options used by TN5250
local OPT_BINARY   = 0x00
local OPT_EOR      = 0x19 -- 25, End Of Record
local OPT_TTYPE    = 0x18 -- 24, Terminal Type
local OPT_NEWENV   = 0x27 -- 39, New Environment

local TTYPE_IS     = 0x00
local TTYPE_SEND   = 0x01

-- 5250 command codes (follow the 0x04 ESC in the data stream) ---------------
local CMD_ESC          = 0x04
local CMD_WRITE_TO_DISPLAY   = 0x11
local CMD_CLEAR_UNIT         = 0x40
local CMD_CLEAR_UNIT_ALT     = 0x20
local CMD_CLEAR_FORMAT_TABLE = 0x50
local CMD_READ_MDT_FIELDS    = 0x52
local CMD_READ_IMMEDIATE     = 0x72
local CMD_READ_INPUT_FIELDS  = 0x42
local CMD_READ_MDT_IMMED     = 0x53
local CMD_WRITE_ERROR_CODE   = 0x21
local CMD_WRITE_ERROR_CODE_WINDOW = 0x22
local CMD_SAVE_SCREEN        = 0x02
local CMD_RESTORE_SCREEN     = 0x12
local CMD_WRITE_STRUCT_FIELD = 0xf3
local CMD_ROLL               = 0x23

-- Read commands tell us the host is finished drawing and is waiting on us.
local READ_COMMANDS = {
  [CMD_READ_MDT_FIELDS] = true,
  [CMD_READ_IMMEDIATE]  = true,
  [CMD_READ_INPUT_FIELDS] = true,
  [CMD_READ_MDT_IMMED]  = true,
}

-- 5250 Write-To-Display order codes -----------------------------------------
local ORDER_SOH = 0x01 -- Start Of Header
local ORDER_RA  = 0x02 -- Repeat to Address
local ORDER_EA  = 0x03 -- Erase to Address
local ORDER_TD  = 0x10 -- Transparent Data
local ORDER_SBA = 0x11 -- Set Buffer Address
local ORDER_WEA = 0x12 -- Write Extended Attribute
local ORDER_IC  = 0x13 -- Insert Cursor
local ORDER_MC  = 0x14 -- Move Cursor
local ORDER_WDSF= 0x15 -- Write to Display Structured Field
local ORDER_SF  = 0x1d -- Start of Field

-- AID (Attention Identifier) codes sent on input --------------------------
local AID = {
  ENTER = 0xf1, HELP = 0xf3, ROLLDOWN = 0xf4, ROLLUP = 0xf5,
  PRINT = 0xf6, CLEAR = 0xbd, PA1 = 0x6c, PA2 = 0x6e, PA3 = 0x6b,
  F1 = 0x31, F2 = 0x32, F3 = 0x33, F4 = 0x34, F5 = 0x35, F6 = 0x36,
  F7 = 0x37, F8 = 0x38, F9 = 0x39, F10 = 0x3a, F11 = 0x3b, F12 = 0x3c,
  F13 = 0xb1, F14 = 0xb2, F15 = 0xb3, F16 = 0xb4, F17 = 0xb5, F18 = 0xb6,
  F19 = 0xb7, F20 = 0xb8, F21 = 0xb9, F22 = 0xba, F23 = 0xbb, F24 = 0xbc,
}

-- Known terminal types and their geometry.
local TERMINALS = {
  ["IBM-3179-2"]  = { rows = 24, cols = 80  }, -- color, 24x80 (default)
  ["IBM-3477-FC"] = { rows = 27, cols = 132 }, -- color, 27x132
  ["IBM-3180-2"]  = { rows = 27, cols = 132 },
  ["IBM-5251-11"] = { rows = 24, cols = 80  },
  ["IBM-5555-C01"]= { rows = 24, cols = 80  },
}

--- A single EBCDIC byte -> ASCII character (code page 037).
local function e2a(byte)
  return drda.StringUtil.toASCII(string.char(byte))
end

Telnet = {}
Telnet.__index = Telnet

--- Create a new TN5250 Telnet object.
function Telnet:new(options)
  options = options or {}
  local o = {
    termtype  = options.termtype or "IBM-3179-2",
    devname   = options.devname,          -- optional DEVNAME via NEW-ENVIRON
    timeout   = options.timeout or 3000,
    isSSL     = true,                     -- try SSL first, fall back to tcp
    -- telnet negotiation state
    negotiated = {},                      -- options we have agreed to
    sent_ttype = false,
    -- 5250 screen state
    rows = 24, cols = 80,
    buffer = {},                          -- 1-based array of single chars
    fields = {},                          -- input fields found on the screen
    cur_attr = 0x20,                      -- current field/char attribute
    cursor_row = 1, cursor_col = 1,
    error_line = nil,
    aid_ready = false,                    -- host issued a Read command
  }
  local geom = TERMINALS[o.termtype]
  if geom then o.rows, o.cols = geom.rows, geom.cols end
  setmetatable(o, self)
  self.__index = self
  o:clear_screen()
  return o
end

--- Disable the SSL-first connection (plain telnet only).
function Telnet:disableSSL()
  self.isSSL = false
end

function Telnet:clear_screen()
  self.buffer = {}
  for i = 1, self.rows * self.cols do
    self.buffer[i] = " "
  end
  self.fields = {}
  self.cursor_row, self.cursor_col = 1, 1
end

-- Buffer-address helpers (1-based row/col like the 5250 data stream) --------
function Telnet:rc_to_index(row, col)
  return (row - 1) * self.cols + col
end

function Telnet:BA_TO_ROW(index)
  return math.floor((index - 1) / self.cols) + 1
end

function Telnet:BA_TO_COL(index)
  return ((index - 1) % self.cols) + 1
end

----------------------------------------------------------------------------
-- Networking
----------------------------------------------------------------------------

--- Connect and run the TN5250 negotiation, reading the first screen.
-- @param host nmap host table or string
-- @param port nmap port table or number
-- @return status boolean, err string on failure
function Telnet:initiate(host, port)
  local opts = { recv_before = true, timeout = self.timeout }
  local socket, first, _, _
  if self.isSSL then
    socket, first = comm.tryssl(host, port, "", opts)
  else
    socket = nmap.new_socket()
    socket:set_timeout(self.timeout)
    local status, err = socket:connect(host, port, "tcp")
    if not status then return false, err end
  end
  if not socket then
    return false, "connection failed"
  end
  self.socket = socket
  self.socket:set_timeout(self.timeout)

  -- feed any bytes comm.tryssl already pulled, then keep reading
  if first and #first > 0 then
    self:feed(first)
  end

  local deadline_tries = 0
  while not self.aid_ready do
    local status, data = self.socket:receive()
    if not status then
      -- a clean EOR before close still counts as a drawn screen
      if data == "EOF" or data == "TIMEOUT" then
        if self:screen_has_content() then break end
      end
      self.socket:close()
      if self:screen_has_content() then
        return true
      end
      return false, ("receive failed: %s"):format(tostring(data))
    end
    self:feed(data)
    deadline_tries = deadline_tries + 1
    if deadline_tries > 50 then break end -- safety valve
  end
  return true
end

function Telnet:screen_has_content()
  for i = 1, #self.buffer do
    if self.buffer[i] ~= " " then return true end
  end
  return false
end

function Telnet:disconnect()
  if self.socket then return self.socket:close() end
end

--- Send a block of raw bytes to the host.
function Telnet:send_data(data)
  stdnse.debug(3, "tn5250: sending %d bytes: %s", #data, stdnse.tohex(data))
  return self.socket:send(data)
end

----------------------------------------------------------------------------
-- Telnet layer: strip IAC sequences, assemble 5250 records (IAC EOR framed)
----------------------------------------------------------------------------

-- Incrementally parse telnet bytes. Completed 5250 records are handed to
-- process_record(). Negotiation replies are written straight back.
function Telnet:feed(data)
  self.rbuf = self.rbuf or {}          -- bytes of the record under assembly
  self.tstate = self.tstate or "DATA"
  self.sb = self.sb or {}

  local i = 1
  local n = #data
  while i <= n do
    local b = data:byte(i)
    local st = self.tstate

    if st == "DATA" then
      if b == IAC then
        self.tstate = "IAC"
      else
        self.rbuf[#self.rbuf + 1] = b
      end
    elseif st == "IAC" then
      if b == IAC then          -- escaped 0xFF in data
        self.rbuf[#self.rbuf + 1] = IAC
        self.tstate = "DATA"
      elseif b == EOR then      -- end of a 5250 record
        self:process_record(self.rbuf)
        self.rbuf = {}
        self.tstate = "DATA"
      elseif b == DO or b == DONT or b == WILL or b == WONT then
        self.tcmd = b
        self.tstate = "OPT"
      elseif b == SB then
        self.sb = {}
        self.tstate = "SB"
      else
        self.tstate = "DATA"    -- ignore other standalone commands
      end
    elseif st == "OPT" then
      self:negotiate(self.tcmd, b)
      self.tstate = "DATA"
    elseif st == "SB" then
      if b == IAC then
        self.tstate = "SB_IAC"
      else
        self.sb[#self.sb + 1] = b
      end
    elseif st == "SB_IAC" then
      if b == SE then
        self:subnegotiate(self.sb)
        self.sb = {}
        self.tstate = "DATA"
      else
        self.sb[#self.sb + 1] = b   -- escaped byte inside SB
        self.tstate = "SB"
      end
    end
    i = i + 1
  end
end

-- Respond to a WILL/WONT/DO/DONT request.
function Telnet:negotiate(cmd, opt)
  local function reply(verb)
    self:send_data(string.char(IAC, verb, opt))
  end

  if cmd == DO then
    if opt == OPT_TTYPE or opt == OPT_BINARY or opt == OPT_EOR then
      if not self.negotiated["WILL" .. opt] then
        self.negotiated["WILL" .. opt] = true
        reply(WILL)
      end
    else
      reply(WONT)               -- decline everything else (incl. NEW-ENVIRON)
    end
  elseif cmd == WILL then
    if opt == OPT_BINARY or opt == OPT_EOR then
      if not self.negotiated["DO" .. opt] then
        self.negotiated["DO" .. opt] = true
        reply(DO)
      end
    else
      reply(DONT)
    end
  elseif cmd == DONT then
    reply(WONT)
  elseif cmd == WONT then
    reply(DONT)
  end
end

-- Handle an SB ... SE sub-negotiation (we only answer TERMINAL-TYPE SEND).
function Telnet:subnegotiate(sb)
  if #sb >= 2 and sb[1] == OPT_TTYPE and sb[2] == TTYPE_SEND then
    local payload = { IAC, SB, OPT_TTYPE, TTYPE_IS }
    for j = 1, #self.termtype do
      payload[#payload + 1] = self.termtype:byte(j)
    end
    payload[#payload + 1] = IAC
    payload[#payload + 1] = SE
    self.sent_ttype = true
    self:send_data(string.char(table.unpack(payload)))
  end
  -- NEW-ENVIRON SEND is intentionally not answered; we decline that option.
end

----------------------------------------------------------------------------
-- 5250 data-stream parsing
----------------------------------------------------------------------------

-- A completed record is an array of bytes beginning with the GDS header.
function Telnet:process_record(bytes)
  local n = #bytes
  if n < 1 then return end

  -- Skip the 10-byte GDS header when present (record type 0x12A0).
  local pos = 1
  if n >= 10 and bytes[3] == 0x12 and bytes[4] == 0xa0 then
    pos = 11
  end

  while pos <= n do
    local b = bytes[pos]
    if b == CMD_ESC then
      pos = pos + 1
      local cmd = bytes[pos]
      pos = pos + 1
      pos = self:handle_command(cmd, bytes, pos)
    else
      pos = pos + 1 -- resync: ignore stray byte outside an ESC command
    end
  end
end

-- Dispatch one 5250 command; returns the new parse position.
function Telnet:handle_command(cmd, bytes, pos)
  if cmd == CMD_CLEAR_UNIT or cmd == CMD_CLEAR_UNIT_ALT then
    self:clear_screen()
    if cmd == CMD_CLEAR_UNIT_ALT then pos = pos + 1 end -- one parameter byte
    return pos
  elseif cmd == CMD_CLEAR_FORMAT_TABLE then
    self.fields = {}
    return pos
  elseif cmd == CMD_WRITE_TO_DISPLAY then
    pos = pos + 2 -- control characters CC1, CC2
    return self:parse_orders(bytes, pos)
  elseif cmd == CMD_WRITE_ERROR_CODE then
    pos = pos + 2 -- CC1, CC2
    return self:parse_orders(bytes, pos)  -- error text drawn on message line
  elseif cmd == CMD_WRITE_ERROR_CODE_WINDOW then
    pos = pos + 4
    return self:parse_orders(bytes, pos)
  elseif READ_COMMANDS[cmd] then
    pos = pos + 2 -- CC1, CC2
    self.aid_ready = true -- host is now waiting for input
    return pos
  elseif cmd == CMD_WRITE_STRUCT_FIELD then
    -- Length-prefixed structured field; skip it wholesale.
    if bytes[pos] and bytes[pos + 1] then
      local len = bytes[pos] * 256 + bytes[pos + 1]
      return pos + math.max(len, 2)
    end
    return pos + 2
  elseif cmd == CMD_SAVE_SCREEN or cmd == CMD_RESTORE_SCREEN then
    return pos
  elseif cmd == CMD_ROLL then
    return pos + 3
  else
    -- Unknown command: stop parsing this record to stay safe.
    return #bytes + 1
  end
end

-- Walk the orders/data that follow a Write-To-Display command.
function Telnet:parse_orders(bytes, pos)
  local n = #bytes
  while pos <= n do
    local b = bytes[pos]
    if b == CMD_ESC then
      return pos -- next command begins; hand back to process_record
    elseif b == ORDER_SBA then
      self.cursor_row = bytes[pos + 1] or 1
      self.cursor_col = bytes[pos + 2] or 1
      pos = pos + 3
    elseif b == ORDER_IC or b == ORDER_MC then
      self.cursor_row = bytes[pos + 1] or self.cursor_row
      self.cursor_col = bytes[pos + 2] or self.cursor_col
      pos = pos + 3
    elseif b == ORDER_RA then
      pos = self:order_repeat(bytes, pos)
    elseif b == ORDER_EA then
      pos = self:order_erase(bytes, pos)
    elseif b == ORDER_SF then
      pos = self:order_start_field(bytes, pos)
    elseif b == ORDER_SOH then
      local len = bytes[pos + 1] or 0
      pos = pos + 2 + len
    elseif b == ORDER_TD then
      local len = (bytes[pos + 1] or 0) * 256 + (bytes[pos + 2] or 0)
      pos = pos + 3 + len
    elseif b == ORDER_WEA then
      pos = pos + 2
    elseif b == ORDER_WDSF then
      local len = (bytes[pos + 1] or 0) * 256 + (bytes[pos + 2] or 0)
      pos = pos + math.max(len + 1, 3)
    elseif b >= 0x20 and b <= 0x3f then
      -- Screen attribute byte: occupies a cell (blank) and sets attribute.
      self.cur_attr = b
      self:put_char(" ")
    elseif b >= 0x40 then
      -- EBCDIC display data.
      self:put_char(e2a(b))
    else
      pos = pos + 1 -- unknown low control byte; skip
      goto continue
    end
    if b >= 0x20 then pos = pos + 1 end
    ::continue::
  end
  return pos
end

-- Place one character at the cursor and advance it.
function Telnet:put_char(ch)
  local idx = self:rc_to_index(self.cursor_row, self.cursor_col)
  if idx >= 1 and idx <= self.rows * self.cols then
    self.buffer[idx] = ch
  end
  self.cursor_col = self.cursor_col + 1
  if self.cursor_col > self.cols then
    self.cursor_col = 1
    self.cursor_row = self.cursor_row + 1
    if self.cursor_row > self.rows then self.cursor_row = 1 end
  end
end

-- RA: Repeat to Address. 0x02 row col char
function Telnet:order_repeat(bytes, pos)
  local row  = bytes[pos + 1] or self.cursor_row
  local col  = bytes[pos + 2] or self.cursor_col
  local char = bytes[pos + 3] or 0x40
  local ch = (char >= 0x40) and e2a(char) or " "
  local target = self:rc_to_index(row, col)
  local idx = self:rc_to_index(self.cursor_row, self.cursor_col)
  local guard = 0
  while idx ~= target and guard < self.rows * self.cols do
    if idx >= 1 and idx <= self.rows * self.cols then self.buffer[idx] = ch end
    self.cursor_col = self.cursor_col + 1
    if self.cursor_col > self.cols then
      self.cursor_col = 1
      self.cursor_row = self.cursor_row + 1
      if self.cursor_row > self.rows then self.cursor_row = 1 end
    end
    idx = self:rc_to_index(self.cursor_row, self.cursor_col)
    guard = guard + 1
  end
  return pos + 4
end

-- EA: Erase to Address. 0x03 row col (fills with nulls -> spaces)
function Telnet:order_erase(bytes, pos)
  local row = bytes[pos + 1] or self.cursor_row
  local col = bytes[pos + 2] or self.cursor_col
  local target = self:rc_to_index(row, col)
  local idx = self:rc_to_index(self.cursor_row, self.cursor_col)
  local guard = 0
  while idx ~= target and guard < self.rows * self.cols do
    if idx >= 1 and idx <= self.rows * self.cols then self.buffer[idx] = " " end
    self.cursor_col = self.cursor_col + 1
    if self.cursor_col > self.cols then
      self.cursor_col = 1
      self.cursor_row = self.cursor_row + 1
      if self.cursor_row > self.rows then self.cursor_row = 1 end
    end
    idx = self:rc_to_index(self.cursor_row, self.cursor_col)
    guard = guard + 1
  end
  return pos + 3
end

-- SF: Start of Field. 0x1D [FFW(2)] [FCW(2)]* attr(1) len(2)
-- The attribute occupies the current cell; the field begins at the next cell.
function Telnet:order_start_field(bytes, pos)
  local p = pos + 1
  local ffw = nil
  -- FFW present when the top two bits of the next byte are '01'.
  if bytes[p] and (bytes[p] & 0xc0) == 0x40 then
    ffw = (bytes[p] * 256) + (bytes[p + 1] or 0)
    p = p + 2
  end
  -- Zero or more FCWs ('10' in the top two bits).
  while bytes[p] and (bytes[p] & 0xc0) == 0x80 do
    p = p + 2
  end
  local attr = bytes[p] or 0x20
  p = p + 1
  local len = (bytes[p] or 0) * 256 + (bytes[p + 1] or 0)
  p = p + 2

  -- The attribute byte sits at the current position and is non-display.
  self.cur_attr = attr
  -- A field without an FFW (output-only) still consumes the attribute cell.
  local attr_row, attr_col = self.cursor_row, self.cursor_col
  self:put_char(" ")

  if ffw then
    -- Input field: its data starts in the cell after the attribute.
    local f = {
      row    = self.cursor_row,
      col    = self.cursor_col,
      length = len,
      attr   = attr,
      ffw    = ffw,
      hidden = self:attr_is_hidden(attr),
    }
    self.fields[#self.fields + 1] = f
  end
  return p
end

-- Non-display attributes in the 0x20-0x3F range: 0x27, 0x2F, 0x37, 0x3F.
function Telnet:attr_is_hidden(attr)
  return (attr & 0x07) == 0x07
end

----------------------------------------------------------------------------
-- Output helpers (consumed by the NSE script)
----------------------------------------------------------------------------

--- Return the rendered screen as a single string (rows separated by \n).
function Telnet:get_screen()
  local lines = {}
  for r = 1, self.rows do
    local start = (r - 1) * self.cols + 1
    local line = table.concat(self.buffer, "", start, start + self.cols - 1)
    lines[r] = (line:gsub("%s+$", "")) -- trim trailing spaces
  end
  -- drop trailing blank lines
  while #lines > 0 and lines[#lines] == "" do
    lines[#lines] = nil
  end
  return table.concat(lines, "\n")
end

--- True if any input field is hidden (non-display).
function Telnet:any_hidden()
  for _, f in ipairs(self.fields) do
    if f.hidden then return true end
  end
  return false
end

--- Return a list of hidden field descriptors {row, col, length}.
function Telnet:hidden_fields()
  local out = {}
  for _, f in ipairs(self.fields) do
    if f.hidden then out[#out + 1] = f end
  end
  return out
end

--- Return every input field found on the screen.
function Telnet:get_fields()
  return self.fields
end

--- Geometry / cursor accessors.
function Telnet:get_rows() return self.rows end
function Telnet:get_cols() return self.cols end
function Telnet:get_cursor() return self.cursor_row, self.cursor_col end

----------------------------------------------------------------------------
-- Sending an AID (used by the script's `commands` argument)
----------------------------------------------------------------------------

-- Parse a command token: a function/AID key name ("F3", "ENTER", "HELP"),
-- optionally with field text, e.g. "ENTER" or "F3". Field text entry uses
-- the form "<row>,<col>=<text>" repeated, followed by a key, e.g.
-- "5,25=HELLO;ENTER" is split by the caller; here one token is one key or
-- one field assignment.
function Telnet:send_aid(aid_name)
  local aid = AID[aid_name:upper()]
  if not aid then
    return false, ("unknown AID/key: %s"):format(aid_name)
  end
  -- Response: cursor row, cursor col, AID, then (no modified fields here).
  local body = string.char(self.cursor_row, self.cursor_col, aid)
  -- Wrap in a GDS header (opcode 0x03 = Put/Get) then IAC EOR.
  local length = #body + 10
  local header = string.pack(">I2", length) ..
                 string.char(0x12, 0xa0, 0x00, 0x00, 0x04, 0x00, 0x00, 0x03)
  self.aid_ready = false
  local ok, err = self:send_data(header .. body .. string.char(IAC, EOR))
  if not ok then return false, err end
  return true
end

--- Read whatever the host sends next (after an AID), updating the screen.
function Telnet:get_all_data(timeout)
  self.socket:set_timeout(timeout or self.timeout)
  local tries = 0
  while not self.aid_ready and tries < 50 do
    local status, data = self.socket:receive()
    if not status then break end
    self:feed(data)
    tries = tries + 1
  end
  return true
end

return _ENV
