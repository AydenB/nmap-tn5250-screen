local stdnse = require "stdnse"
local shortport = require "shortport"
local tn5250 = require "tn5250"

description = [[
Connects to an IBM i (AS/400, iSeries) tn5250 'server' and returns the
screen (typically the sign-on screen).

Input fields are listed below the screen with (row, col) coordinates; any
non-display field (for example the password entry) is flagged as hidden.

This is the tn5250 counterpart to Nmap's tn3270-screen script and reuses the
same approach: a tn5250 library performs the RFC 1205 / RFC 2877 negotiation,
reads the 5250 data stream and renders the display.
]]

---
-- @usage
-- nmap --script tn5250-screen -p 23 <host>
-- nmap --datadir . --script ./scripts/tn5250-screen.nse -p 23 <host>
--
-- @output
-- PORT   STATE SERVICE
-- 23/tcp open  tn5250
-- | tn5250-screen:
-- |   screen:
-- |              Welcome to PUB400.COM * your public IBM i server
-- |                                            Server name . . . :   PUB400
-- |                                            Subsystem . . . . :   QINTER2
-- |                                            Display name. . . :   QPADEV002D
-- |     Your user name:
-- |     Password (max. 128):
-- |     ...
-- |   input fields:
-- |     (5, 25): visible input field, length 10
-- |   hidden fields:
-- |_    (6, 25): non-display input field, length 128
--
-- @args tn5250-screen.commands semi-colon separated list of function keys to
--       send before capturing the final screen, e.g. "F3" or "ENTER".
--       Intended for navigating public screens; it does not log in.
-- @args tn5250-screen.termtype terminal type to request (default IBM-3179-2,
--       24x80). Use IBM-3477-FC for a 27x132 screen.
-- @args tn5250-screen.timeout socket timeout in milliseconds (default 3000).
-- @args tn5250-screen.nossl disable the SSL-first connection attempt.
--
-- @changelog
-- 2026-10-04 - v0.1 - created, modeled on tn3270-screen by Soldier of Fortran
--

author = "Ayden"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service({23, 992}, {"tn5250", "telnet"})

local field_mt = {
  __tostring = function(t)
    local kind = t.hidden and "non-display" or "visible"
    return ("(%d, %d): %s input field, length %d"):format(t.row, t.col, kind, t.length)
  end,
}

action = function(host, port)
  local commands = stdnse.get_script_args(SCRIPT_NAME .. ".commands")
  local termtype = stdnse.get_script_args(SCRIPT_NAME .. ".termtype")
  local timeout  = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".timeout"))
  local nossl    = stdnse.get_script_args(SCRIPT_NAME .. ".nossl")

  local t = tn5250.Telnet:new({
    termtype = termtype,
    timeout  = timeout,
  })
  if nossl then t:disableSSL() end

  local status, err = t:initiate(host, port)
  if not status then
    stdnse.debug(1, "Could not initiate TN5250: %s", tostring(err))
    return nil
  end

  if commands then
    local run = stdnse.strsplit(";%s*", commands)
    for i = 1, #run do
      stdnse.debug(1, "Sending key (#%d of %d): %s", i, #run, run[i])
      local ok, serr = t:send_aid(run[i])
      if ok then
        t:get_all_data()
      else
        stdnse.debug(1, "Key send failed: %s", tostring(serr))
      end
    end
  end

  local out = stdnse.output_table()
  out.screen = t:get_screen()

  local visible, hidden = {}, {}
  for _, f in ipairs(t:get_fields()) do
    setmetatable(f, field_mt)
    if f.hidden then
      hidden[#hidden + 1] = tostring(f)
    else
      visible[#visible + 1] = tostring(f)
    end
  end
  if #visible > 0 then out["input fields"] = visible end
  if #hidden  > 0 then out["hidden fields"] = hidden end

  t:disconnect()
  return out
end
