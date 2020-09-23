# The detector works be looking for a high number of NetrServerReqChallenge and
# NetrServerAuthenticate3 Netlogon commands, followed by NetrServerPasswordSet2
# with above the necessary number of bytes for the 516 byte all zero password.
# This must happen in `expire` time (defaults to 2 minutes) to be considered a
# successful attack.
#
# There are three redef'able constants: `expire`, `cutoff`, and
# `notice_on_exploit_only`. `cutoff` is the minumum number of the first two
# operators that must be seen to consider an attack to have been attempted. This
# is low, but I have not seen false positives in my testing. If your network is
# different, bump this value up. If `notice_on_exploit_only` is set to T, only a
# successful exploit will generate a notice.
module Zerologon;

redef enum Notice::Type += {
    Zerologon_Attempt,
    Zerologon_Password_Change
};

export {
    # Time window of attack. A higher value will catch more careful attackers,
    # but at the potential cost of more false positives.
    global expire = 2min &redef;
    # Minimum required number of NetrServerReqChallenge/NetrServerAuthenticate3 pairs
    # before considering it to be an attempted attack.
    global cutoff = 20 &redef;
    # Change this to T if you only want a notice to be generated for a successful exploit.
    global notice_on_exploit_only = F &redef;
    }

type Counter: record {
    req_challenge: count &default=0;
    req_auth3: count &default=0;
    req_pass_set2: count &default=0;
    saw_pass_stub_len: bool &default=F;

    resp_challenge: count &default=0;
    resp_auth3: count &default=0;
    resp_pass_set2: count &default=0;
    };

# Operators involved in attack
global ops: set[string] = { "NetrServerReqChallenge", "NetrServerAuthenticate3", "NetrServerPasswordSet2" };

# Counter is based on c$id$resp_h because a clever attacker could try the attack
# from multiple hosts.
global counters: table[addr] of Counter &create_expire=expire;

# Given two counter objects, increment all fields in the first by the value of
# the fields in the second.
function inc(c1: Counter, c2: Counter)
    {
    c1$req_challenge += c2$req_challenge;
    c1$req_auth3 += c2$req_auth3;
    c1$req_pass_set2 += c2$req_pass_set2;
    c1$saw_pass_stub_len = c1$saw_pass_stub_len || c2$saw_pass_stub_len;
    c1$resp_challenge += c2$resp_challenge;
    c1$resp_auth3 += c2$resp_auth3;
    c1$resp_pass_set2 += c2$resp_pass_set2;
    }

function check_and_alert(cid: conn_id)
    {
    # This may have already been deleted if we found NetrServerPasswordSet2
    # before the attempt timer was launched.
    if (cid$resp_h !in counters)
        {
        return;
        }
    local rec = counters[cid$resp_h];
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
            $id=cid,
            $identifier=cat(cid$resp_h)
        ]);
        }
    delete counters[cid$resp_h];
    }

event check_for_attempt(cid: conn_id)
    {
    check_and_alert(cid);
    }

event Zerologon::increment_counter(cid: conn_id, addend: Counter, opname_and_src: string)
    {
    if (cid$resp_h !in counters)
        {
        counters[cid$resp_h] = Counter();
        # In case we never see a password change with NetrServerPasswordSet2,
        # check for a long enough run of attempts before the counter expires to
        # generate a notice for an unsuccessful attempt.
        schedule expire - 10secs { check_for_attempt(cid) };
        }
    inc(counters[cid$resp_h], addend);
    # If we've seen password set as a response, check for the required length
    # of messages and alert.
    if (opname_and_src == "NetrServerPasswordSet2:dce_rpc_response")
        {
        check_and_alert(cid);
        }
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

    local addend = Counter();
    switch opname
        {
        case "NetrServerReqChallenge":
            addend$req_challenge = 1;
            break;
        case "NetrServerAuthenticate3":
            addend$req_auth3 += 1;
            break;
        case "NetrServerPasswordSet2":
            if (stub_len >= 516) # The plaintext password protocol for Netlogon is 516 bytes long. In order for the attack to succeed, it must be this fixed length of all zeroes. However, the stub length also includes the domain controller's domain and other headers.
                {
                addend$saw_pass_stub_len = T;
                }
            break;
        }

@if (Cluster::is_enabled())
    Cluster::publish_hrw(Cluster::proxy_pool, c$id$resp_h, Zerologon::increment_counter, c$id, addend, cat(opname, ":", "dce_rpc_request"));
@else
    event Zerologon::increment_counter(c$id, addend, cat(opname, ":", "dce_rpc_request"));
@endif
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

    local addend = Counter();
    switch opname
        {
        case "NetrServerReqChallenge":
            addend$resp_challenge = 1;
            break;
        case "NetrServerAuthenticate3":
            addend$resp_auth3 = 1;
            break;
        case "NetrServerPasswordSet2":
            addend$resp_pass_set2 = 1;
            break;
        }

@if (Cluster::is_enabled())
    Cluster::publish_hrw(Cluster::proxy_pool, c$id$resp_h, Zerologon::increment_counter, c$id, addend, cat(opname, ":", "dce_rpc_response"));
@else
    event Zerologon::increment_counter(c$id, addend, cat(opname, ":", "dce_rpc_response"));
@endif
    }
