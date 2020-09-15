# The detector works be looking for a high number of NetrServerReqChallenge and
# NetrServerAuthenticate3 Netlogon commands, followed by NetrServerPasswordSet2
# with above the necessary number of bytes for the 516 byte all zero password.
# This must happen in `expire` time (defaults to 2 minutes) to be considered a
# successful attack.
#
# There are three redef'able constants in `cluster.zeek`: `expire`, `cutoff`,
# and `notice_on_exploit_only`. `cutoff` is the minumum number
# of the first two operators that must be seen to consider an attack to have
# been attempted. This is low, but I have not seen many false positives in my
# testing. If your network is different, bump this value up.
# If `notice_on_exploit_only` is set to T, only a successful exploit will
# generate a notice.
module Zerologon;

redef enum Notice::Type += {
    Zerologon_Attempt,
    Zerologon_Password_Change
};

# Operators involved in attack
global ops: set[string] = { "NetrServerReqChallenge", "NetrServerAuthenticate3", "NetrServerPasswordSet2" };

function check_and_alert(c: connection)
    {
    # This may have already been deleted if we found NetrServerPasswordSet2
    # before the attempt timer was launched.
    if (c$id$resp_h !in counters)
        return;
    local rec = counters[c$id$resp_h];
    if (rec$resp_challenge > cutoff && rec$resp_auth3 > cutoff)
        {
        local note = Zerologon_Attempt;
        local msg = "CVE-2020-1472 attempt";
        if (rec$resp_pass_set2 > 0 && rec$saw_pass_stub_len)
            {
            note = Zerologon_Password_Change;
            msg = "CVE-2020-1472 domain controller password change successful";
            }
        # Don't generate a Notice if we are only alerting on successful exploits.
        else if (notice_on_exploit_only)
            {
            return;
            }
        NOTICE([$note=note,
            $msg=msg,
            $conn=c,
            $identifier=cat(c$id$resp_h)
        ]);
        }
    delete counters[c$id$resp_h];
    }

event check_for_attempt(c: connection)
    {
    check_and_alert(c);
    }

event dce_rpc_request(c: connection, fid: count, ctx_id: count, opnum: count, stub_len: count)
    {
    if (!c$dce_rpc_state?$uuid)
        {
        return;
        }
    local opname = DCE_RPC::operations[c$dce_rpc_state$uuid, opnum];
    if (opname !in ops)
        {
        return;
        }
    if (c$id$resp_h !in counters)
        {
        counters[c$id$resp_h] = Counter();
        # In case we never see a password change with NetrServerPasswordSet2,
        # check for a long enough run of attempts before the counter expires to
        # generate a notice for an unsuccessful attempt.
        if (!notice_on_exploit_only)
            {
            schedule expire - 10secs { check_for_attempt(c) };
            }
        }

    local c2 = Counter();
    switch opname
        {
        case "NetrServerReqChallenge":
            c2$req_challenge = 1;
            break;
        case "NetrServerAuthenticate3":
            c2$req_auth3 += 1;
            break;
        case "NetrServerPasswordSet2":
            if (c$id$resp_h in counters && stub_len >= 516) # The plaintext password protocol for Netlogon is 516 bytes long. In order for the attack to succeed, it must be this fixed length of all zeroes. However, the stub length also includes the domain controller's domain and other headers.
                {
                c2$saw_pass_stub_len = T;
                }
            break;
        }
    # Increment, and broadcast to cluster
    inc(counters[c$id$resp_h], c2);
    event counter_incremented(c$id$resp_h, c2);
    }

event dce_rpc_response(c: connection, fid: count, ctx_id: count, opnum: count, stub_len: count)
    {
    if (!c$dce_rpc_state?$uuid)
        {
        return;
        }
    local opname = DCE_RPC::operations[c$dce_rpc_state$uuid, opnum];
    if (opname !in ops)
        {
        return;
        }
    if (c$id$resp_h !in counters)
        {
        counters[c$id$resp_h] = Counter();
        }

    local c2 = Counter();

    switch opname
        {
        case "NetrServerReqChallenge":
            c2$resp_challenge = 1;
            break;
        case "NetrServerAuthenticate3":
            c2$resp_auth3 = 1;
            break;
        case "NetrServerPasswordSet2":
            c2$resp_pass_set2 = 1;
            break;
        }
    # Increment, and broadcast to cluster
    inc(counters[c$id$resp_h], c2);
    event counter_incremented(c$id$resp_h, c2);
    if (opname == "NetrServerPasswordSet2")
        {
        check_and_alert(c);
        }
    }
