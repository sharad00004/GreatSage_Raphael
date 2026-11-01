"""Detects network anomalies and links findings to packet evidence."""
from collections import defaultdict, Counter, deque, OrderedDict
from dataclasses import dataclass, asdict
import heapq
from .capture import read_capture

@dataclass
class Finding:
    title: str
    category: str
    severity: str
    confidence: str
    explanation: str
    cause: str
    fix: str
    evidence: list


MAX_FINDINGS = 1000


def analyze(packets, cancel=None, inventory=None, notes=None):
    findings = []
    omitted = 0
    finding_heap = []
    serial = 0
    inventory = inventory or {}
    inventory_mismatches = defaultdict(list)
    def add(title, category, severity, confidence, explanation, cause, fix, evidence):
        nonlocal omitted, serial
        serial+=1
        score={'High':3,'Medium':2,'Low':1}[severity]
        slot=None
        if len(findings)>=MAX_FINDINGS:
            omitted+=1
            if not finding_heap:
                finding_heap.extend(({'High':3,'Medium':2,'Low':1}[f.severity],-i,i) for i,f in enumerate(findings))
                heapq.heapify(finding_heap)
            if score<=finding_heap[0][0]:return
            slot=finding_heap[0][2]
            heapq.heapreplace(finding_heap,(score,-serial,slot))
        finding=Finding(title,category,severity,confidence,explanation,cause,fix,sorted(set(evidence))[:100])
        if slot is None:findings.append(finding)
        else:findings[slot]=finding
    arp = defaultdict(OrderedDict); arp_conflicts = defaultdict(dict); scans = defaultdict(list); sequences = {}; generations = defaultdict(int); retrans = defaultdict(list); resets = defaultdict(list)
    recent_data = defaultdict(lambda: deque(maxlen=256))
    dns = {}; answered = {}; inconsistent = []; failures = defaultdict(list); delays = []; dhcp = defaultdict(list); mtu = []; unreachable = defaultdict(list)
    for p in packets:
        if cancel is not None and cancel.is_set():
            from .capture import CaptureError
            raise CaptureError('Analysis cancelled.')
        flow = (p.source, p.sport, p.destination, p.dport)
        if p.protocol == 'ARP' and p.info.get('op') in (1, 2):
            allowed = inventory.get('arp_bindings', {}).get(p.source)
            if allowed and p.info['mac'] not in allowed:
                inventory_mismatches[('ARP claim differs from trusted inventory', p.source)].append(p.number)
        if p.protocol == 'DHCP' and p.info.get('op') == 2 and p.info.get('message_type') in (2, 5):
            allowed = inventory.get('dhcp_servers', [])
            server = p.info.get('server', p.source)
            if allowed and server not in allowed:
                inventory_mismatches[('Unapproved DHCP server observed', server)].append(p.number)
        if p.protocol == 'DNS' and p.info['response']:
            for name, address in p.info.get('answers', []):
                allowed = inventory.get('dns_records', {}).get(name)
                if allowed and address not in allowed:
                    inventory_mismatches[('DNS answer differs from trusted inventory', name)].append(p.number)
        if p.protocol == 'ARP' and p.source != '0.0.0.0' and p.info.get('op') in (1, 2):
            for mac,previous in arp[p.source].items():
                if mac!=p.info['mac'] and 0<=p.time-previous.time<=60:
                    arp_conflicts[p.source][mac]=previous.number
                    arp_conflicts[p.source][p.info['mac']]=p.number
            arp[p.source][p.info['mac']]=p
            arp[p.source].move_to_end(p.info['mac'])
            if len(arp[p.source])>32:arp[p.source].popitem(last=False)
        elif p.protocol == 'TCP':
            flags = p.info['flags']
            if flags & 2 and not flags & 16:
                scans[(p.source, p.destination)].append(p)
                # A fresh SYN starts a new connection and invalidates old sequence evidence.
                generations[flow] += 1
                generations[(p.destination,p.dport,p.source,p.sport)] += 1
            if flags & 4: resets[(p.source, p.destination)].append(p.number)
            if p.info['length']:
                key = (flow, generations[flow], p.info['seq'], p.info['length'], p.info.get('payload_hash'))
                previous = sequences.get(key)
                if previous and 0 < p.time - previous.time <= 60:
                    retrans[flow].extend([previous.number, p.number])
                # TCP retransmissions may use different segment boundaries. The comparison
                # checks recent sequence ranges and exact payload fingerprints.
                # Signed 32-bit subtraction handles sequence-number wraparound.
                if not (previous and 0 < p.time - previous.time <= 60):
                    for earlier in reversed(recent_data[(flow, generations[flow])]):
                        if not 0 < p.time - earlier.time <= 60: continue
                        if (p.info['seq'], p.info['length']) == (earlier.info['seq'], earlier.info['length']): continue
                        delta = (p.info['seq'] - earlier.info['seq'] + 2**31) % 2**32 - 2**31
                        if delta < earlier.info['length'] and delta + p.info['length'] > 0:
                            retrans[flow].extend([earlier.number, p.number]); break
                recent_data[(flow, generations[flow])].append(p)
                sequences[key] = p
        elif p.protocol == 'DNS':
            if not p.info['response']:
                question = tuple(tuple(q) for q in p.info.get('questions', []))
                key = (flow, p.info['id'], question)
                dns.setdefault(key, p)
                answered.pop(key, None)
            else:
                reverse = (p.destination, p.dport, p.source, p.sport)
                question = tuple(tuple(q) for q in p.info.get('questions', []))
                key = (reverse, p.info['id'], question)
                query = dns.pop(key, None)
                values = frozenset(tuple(a) for a in p.info.get('answers', []))
                previous = answered.get(key)
                if previous and not p.info.get('truncated') and not previous[0].info.get('truncated') and 0 <= p.time - previous[0].time <= 5 and values and previous[1] and values != previous[1]:
                    inconsistent.extend([previous[0].number, p.number])
                if query or previous:
                    answered[key] = (p, values)
                if p.info['rcode']:
                    failures[(p.source, p.info['rcode'])].append(p.number)
                if query and p.time - query.time >= 1:
                    delays.append((query.number, p.number, p.time-query.time))
        elif p.protocol == 'DHCP' and p.info['op'] == 2 and p.info.get('message_type') in (2, 5):
            dhcp[p.info.get('server', p.source)].append(p.number)
        elif (p.protocol == 'ICMP' and p.info['type'] == 3 and p.info['code'] == 4) or (p.protocol == 'ICMPv6' and p.info['type'] == 2):
            mtu.append(p.number)
        elif (p.protocol == 'ICMP' and p.info['type'] == 3) or (p.protocol == 'ICMPv6' and p.info['type'] == 1):
            unreachable[(p.protocol,p.source,p.info['code'])].append(p.number)
    for (label, identity), evidence in inventory_mismatches.items():
        add(f'{label}: {identity}', 'Possible attack', 'High', 'High',
            'Captured traffic differs from the operator-supplied trusted inventory.',
            'A stale inventory or legitimate infrastructure change; if the inventory is current, possible impersonation, DNS redirection or unauthorized DHCP service.',
            'Verify the inventory with the network owner, then investigate the referenced device or response. An inventory mismatch proves a policy discrepancy, not malicious intent.', evidence)
    if inconsistent:
        add('Conflicting DNS answers for one transaction', 'Needs investigation', 'High', 'Medium',
            'Different address answers arrived for the same DNS endpoints, question and transaction within five seconds.',
            'Resolver inconsistency, duplicated transaction IDs, a capture artifact, or possible DNS response injection. This does not prove hijacking.',
            'Compare the answers with the authorized resolver and DNSSEC validation results; investigate the responder before trusting the answer.', inconsistent)
    end_time = max((p.time for p in packets), default=0)
    unanswered = [p.number for p in dns.values() if end_time - p.time >= 3]
    if unanswered:
        add('DNS queries without observed replies', 'Network fault', 'Medium', 'Low',
            f'{len(unanswered)} DNS query transaction(s) had no matching reply with at least three seconds of later captured traffic.',
            'Resolver or path failure, capture loss, an asymmetric capture, or replies outside the capture window.',
            'Check resolver reachability and capture both directions. An absent response in a capture does not prove the server failed.', unanswered)
    for address, macs in arp_conflicts.items():
        if len(macs) > 1:
            add(f'Conflicting ARP claims for {address}', 'Needs investigation', 'High', 'Medium',
                f'{len(macs)} different MAC addresses advertised the same IPv4 address within a 60-second observation window.',
                'Duplicate addressing, router failover, proxy ARP, or possible ARP spoofing.',
                'Compare these MAC addresses with the authorized device inventory; check DHCP leases and switch ports before isolating a device.', list(macs.values()))
    for (source, destination), attempts in scans.items():
        window = []; counts = Counter(); left = 0; evidence = []
        for p in sorted(attempts, key=lambda p: p.time):
            window.append(p); counts[p.dport] += 1
            while p.time - window[left].time > 10:
                counts[window[left].dport] -= 1
                if not counts[window[left].dport]: del counts[window[left].dport]
                left += 1
            if len(counts) >= 12:
                evidence = [q.number for q in window[left:]]; break
        if evidence:
            add(f'Possible port scan: {source} → {destination}', 'Possible attack', 'High', 'Medium',
                'TCP connection attempts touched at least 12 different ports on one host within 10 seconds.',
                'Port discovery, an authorized scanner, or an application opening many services.',
                'Confirm whether the source is an approved scanner; review firewall logs and restrict unnecessary exposed services.', evidence)
    for flow, evidence in retrans.items():
        add(f'Repeated TCP data: {flow[0]} → {flow[2]}', 'Network fault', 'Medium', 'Medium',
            'TCP payload sequence ranges overlapped within 60 seconds. Exact segment repeats also match payload fingerprints; changed segment boundaries are compared against the last 256 data packets per connection direction.',
            'Possible packet loss or delayed acknowledgments; capture duplication, resegmentation and NIC offload can also produce overlapping sequence ranges.',
            'Inspect both endpoints and link errors; compare capture locations before concluding packet loss.', evidence)
    for hosts, evidence in resets.items():
        add(f'TCP connection reset: {hosts[0]} → {hosts[1]}', 'Network fault', 'Low', 'High',
            f'{len(evidence)} TCP reset packet(s) abruptly ended or refused a connection.',
            'A closed service, application behavior, or a firewall rejecting traffic.',
            'Check the destination service and firewall policy; occasional resets may be normal.', evidence)
    for (server, code), evidence in failures.items():
        label = {2: 'server failure', 3: 'name does not exist', 5: 'query refused'}.get(code, f'error {code}')
        add(f'DNS {label}: {server}', 'Network fault', 'Medium' if code != 3 else 'Low', 'High',
            f'The DNS server returned {len(evidence)} unsuccessful response(s).',
            'A missing domain, DNS server configuration, or upstream resolution failure.',
            'Verify the requested name and configured resolver. Check upstream DNS reachability if valid names fail.', evidence)
    if delays:
        add('Slow DNS responses', 'Network fault', 'Medium', 'Medium',
            f'{len(delays)} matched DNS transaction(s) took at least one second.',
            'Resolver load, upstream delays, or capture timing artifacts.',
            'Compare resolver response times and inspect upstream connectivity.', [n for a,b,_ in delays for n in (a,b)])
    if len(dhcp) > 1:
        add('Multiple DHCP servers observed', 'Needs investigation', 'High', 'Medium',
            f'{len(dhcp)} server identities sent DHCP offers or acknowledgments (option 54, falling back to source IP).',
            'Authorized redundant DHCP servers, DHCP relays, or a possible rogue server.',
            'Compare server identifiers with approved DHCP infrastructure; inspect relay configuration and enable DHCP snooping where appropriate.', [n for ids in dhcp.values() for n in ids])
    for (protocol,source,code),evidence in unreachable.items():
        labels={0:'network',1:'host',3:'port',9:'administratively blocked',10:'administratively blocked',13:'administratively blocked'} if protocol=='ICMP' else {0:'route',1:'administratively blocked',3:'address',4:'port'}
        reason=labels.get(code,f'code {code}')
        add(f'{protocol} unreachable ({reason}): {source}', 'Network fault', 'Medium', 'High',
            f'{len(evidence)} destination-unreachable message(s) were returned. Packet metadata includes the quoted original endpoint when available.',
            'A closed UDP service, missing route, unreachable host or firewall rejection, depending on the ICMP code.',
            'Inspect the quoted destination and port, verify the service and route, and review firewall policy. Error messages can be forged and do not prove intent.',evidence)
    if mtu:
        add('Path MTU feedback observed', 'Network fault', 'Medium', 'High',
            'An ICMP fragmentation-needed or IPv6 Packet Too Big message reported a path MTU constraint. Inspect the packet metadata for the advertised MTU.',
            'The path may use a smaller MTU, often because of a tunnel or VPN.',
            'Check interface and tunnel MTUs; allow ICMP fragmentation-needed feedback and verify path MTU discovery.', mtu)
    if omitted and notes is not None:notes.append(f'Finding safety limit reached: {omitted} further finding groups omitted; narrow the capture before drawing conclusions.')
    return sorted(findings, key=lambda f: {'High': 0, 'Medium': 1, 'Low': 2}[f.severity])


def inspect(path, cancel=None, inventory=None):
    packets, warnings = read_capture(path, cancel)
    if any(p.protocol=='IPv6' for p in packets): warnings.append('Some IPv6 traffic has an unsupported next-header or is fragmented; it is listed without transport diagnosis.')
    if any(p.info.get('fragment') for p in packets): warnings.append('Fragmented IP traffic is listed but not reassembled or diagnosed.')
    warnings.append('DNS hijacking is not proven: conflicting answers need independent resolver/DNSSEC corroboration. DNS over TCP and encrypted DNS are not diagnosed. No clean bill of health is implied by zero findings.')
    findings=analyze(packets,cancel,inventory,warnings)
    metadata=[]
    for p in packets:
        if cancel is not None and cancel.is_set():
            from .capture import CaptureError
            raise CaptureError('Analysis cancelled.')
        # Packet dictionaries contain JSON-compatible values. Reusing these
        # dictionaries avoids a second copy of every decoded packet.
        metadata.append(vars(p))
    return {'schema_version': 1, 'duration_seconds': max((p.time for p in packets),default=0)-min((p.time for p in packets),default=0), 'inventory_used': bool(inventory and any(inventory.values())), 'packet_count': len(packets), 'protocols': dict(Counter(p.protocol for p in packets)),
            'warnings': warnings, 'findings': [asdict(f) for f in findings], 'packets': metadata}
