# Reverse Path Filtering (rp_filter) in VPN Context

## What is Reverse Path Filtering?

**Reverse Path Filtering (rp_filter)** is a Linux kernel security feature that validates incoming packets by checking if the source IP address could be reached through the interface the packet arrived on. It helps prevent IP spoofing attacks.

## How It Works

When a packet arrives on an interface, the kernel performs a reverse path check:

1. **Question**: "If I wanted to send a packet to this source IP, would I use this same interface?"
2. **If NO** → Packet is dropped (potential spoofing attack)
3. **If YES** → Packet is accepted

### rp_filter Modes

Linux supports three modes (configured via `/proc/sys/net/ipv4/conf/<interface>/rp_filter`):

- **0 (Disabled)**: No source validation
- **1 (Strict)**: Packet must arrive on the interface that would be used to reach the source
- **2 (Loose)**: Source address must be reachable via any interface

## Why It Causes Problems with VPNs

In a VPN setup, packets undergo address translation and routing that can violate rp_filter's expectations:

### Example Scenario (DTLS VPN):

**1. Server receives encrypted packet:**
```
Interface: veth1 (192.168.100.x network)
Source IP: 192.168.100.1 (client's physical IP)
✅ rp_filter check passes - valid route back through veth1
```

**2. Packet is decrypted and written to TUN:**
```
Interface: tun1
Source IP: 10.8.0.1 (client's VPN tunnel IP)
Destination IP: 10.9.0.254 (server's VPN IP)
```

**3. Server generates response:**
```
Source IP: 10.9.0.254
Destination IP: 10.8.0.1
Kernel routes through: tun1 (correct)
```

**4. Response packet read from TUN:**
```
Interface: tun1
Source IP: 10.9.0.254
Destination IP: 10.8.0.1
```

**5. Kernel needs to route to 10.8.0.1:**
```
With strict rp_filter:
- Check: "Can I reach 10.8.0.1 through tun1?"
- If routing table doesn't have explicit route: ❌ FAIL
- Packet dropped
```

## When to Disable rp_filter

### Scenarios Requiring Disabled rp_filter:

1. **Asymmetric Routing**
   - Packets arrive on one interface
   - Responses go out through a different interface

2. **VPN/Tunnel Configurations**
   - Packets undergo address translation
   - Source addresses don't match physical network topology

3. **Multi-Interface Setups**
   - Complex routing with multiple paths
   - Load balancing or failover configurations

4. **Network Namespaces**
   - Isolated network environments
   - Non-standard routing topologies

### When You DON'T Need to Disable It:

- Simple point-to-point VPN with proper routes
- Network namespaces with complete isolation
- Proper routing table configuration
- When using loose mode (rp_filter=2) is sufficient

## Testing Without Disabling rp_filter

In the DTLS VPN implementation with network namespaces, you may not need to disable rp_filter because:

1. ✅ Proper routes are configured automatically
2. ✅ Network namespaces provide isolation
3. ✅ Each namespace has its own routing table

### Test Procedure:

1. **Remove rp_filter disabling from setup script:**
```bash
# Comment out or remove these lines:
# sudo ip netns exec client sysctl -w net.ipv4.conf.all.rp_filter=0
# sudo ip netns exec server sysctl -w net.ipv4.conf.all.rp_filter=0
```

2. **Run the VPN and test:**
```bash
# Setup namespaces
./setup_test_env.sh

# Start server
sudo ip netns exec server ./build/server 4433 certs/server_cert.pem certs/server_key.pem 10.9.0.254

# Start client (in another terminal)
sudo ip netns exec client ./build/client 192.168.100.2 4433 10.8.0.1

# Test connectivity
sudo ip netns exec client ping -I tun0 10.9.0.254
```

3. **If it works** → rp_filter is not interfering
4. **If it fails** → Check kernel logs and re-enable the rp_filter=0 setting

## Security Considerations

### Production Recommendations:

1. **Keep rp_filter enabled globally:**
```bash
sysctl -w net.ipv4.conf.default.rp_filter=1
sysctl -w net.ipv4.conf.all.rp_filter=1
```

2. **Disable only on specific interfaces if needed:**
```bash
# Only disable on VPN tunnel interface
sysctl -w net.ipv4.conf.tun0.rp_filter=0
sysctl -w net.ipv4.conf.tun1.rp_filter=0
```

3. **Use loose mode as compromise:**
```bash
# Loose mode: source must be reachable via any interface
sysctl -w net.ipv4.conf.tun0.rp_filter=2
```

4. **Monitor for spoofing attempts:**
```bash
# Check dropped packets
netstat -s | grep -i "reverse path"
```

### Why It's a Security Feature:

Reverse path filtering prevents:
- **IP Spoofing**: Attackers sending packets with fake source addresses
- **DDoS Amplification**: Spoofed packets used in reflection attacks
- **Network Reconnaissance**: Probing with forged source addresses

Disabling it reduces security, so only do so when necessary and on specific interfaces.

## Debugging rp_filter Issues

### Check Current Settings:

```bash
# Check all interfaces
sysctl -a | grep rp_filter

# Check specific interface
cat /proc/sys/net/ipv4/conf/tun0/rp_filter
```

### Enable Logging:

```bash
# Log dropped packets
iptables -A INPUT -m rpfilter --invert -j LOG --log-prefix "RPF-DROP: "
```

### Check Kernel Logs:

```bash
# View dropped packets
dmesg | grep -i "martian"
journalctl -k | grep -i "rp_filter"
```

## Summary

- **rp_filter** validates that packets arrive on the expected interface
- **VPNs often need it disabled** due to address translation and routing
- **Network namespaces may not require disabling** if routes are proper
- **Test without disabling first** - only disable if necessary
- **Disable per-interface in production** for better security
- **Use loose mode (2)** as a compromise between security and functionality

## References

- Linux kernel documentation: `Documentation/networking/ip-sysctl.txt`
- RFC 3704: Ingress Filtering for Multihomed Networks
- `man 7 ip` - Linux IP protocol implementation