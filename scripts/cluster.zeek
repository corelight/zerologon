module Zerologon;

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

# Synchronize additions to global counter data structure
global counter_increment_w2p: event(resp_h: addr, c2: Counter);
global counter_increment_p2w: event(resp_h: addr, c2: Counter);
global counter_incremented: event(resp_h: addr, c2: Counter);
global inc: function(c1: Counter, c2: Counter);
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

@if (Cluster::is_enabled())

@if (Cluster::local_node_type() == Cluster::PROXY)

event zeek_init()
    {
    Broker::auto_publish(Cluster::worker_topic, Zerologon::counter_increment_p2w);
    }

event Zerologon::counter_increment_w2p(resp_h: addr, c2: Counter)
    {
    event Zerologon::counter_increment_p2w(resp_h, c2);
    }


@endif

@if (Cluster::local_node_type() == Cluster::WORKER)

event zeek_init()
    {
    Broker::auto_publish(Cluster::proxy_topic, Zerologon::counter_increment_w2p);
    }

event Zerologon::counter_incremented(resp_h: addr, c2: Counter)
    {
    event Zerologon::counter_increment_w2p(resp_h, c2);
    }

event Zerologon::counter_increment_p2w(resp_h: addr, c2: Counter)
    {
    Cluster::log(fmt("[proxy->worker] cluster add c2: %s", c2));
    if (resp_h !in counters)
        {
        counters[resp_h] = Counter();
        }
    inc(counters[resp_h], c2);
    }

@endif

@endif