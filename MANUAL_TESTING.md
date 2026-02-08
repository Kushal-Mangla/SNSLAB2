# Manual Testing Guide - MCC and Drone Communication

## 🧪 Complete Manual Testing Procedure

---

## **Setup Phase**

### **Terminal 1: Start MCC Server**
```bash
cd /home/kushal/Desktop/Sem6/SNS/Assign2
./scripts/run_mcc.sh
```

**Expected Output:**
```
╔════════════════════════════════════════════════════════════╗
║   UAV Command and Control System - Mission Control Center  ║
╚════════════════════════════════════════════════════════════╝

[MCC] Initializing Mission Control Center...
[MCC] Security Level: 2048 bits

[MCC] Generating ElGamal parameters (SL=2048)...
[MCC] This may take a few moments...
Generating 2048-bit prime (this may take a moment)...
Prime generated: 2048 bits
Generator found: 5

[MCC] ✓ Prime p generated: 2048 bits
[MCC] ✓ Generator g: 5
[MCC] ✓ Public key y: 2048 bits
[MCC] Cryptographic initialization complete!

[MCC] Server started on 127.0.0.1:9999
[MCC] Waiting for drone connections...

====================================================================
MCC Command Interface
====================================================================
Commands:
  list          - Show all authenticated drones
  broadcast <cmd> - Send command to all drones
  shutdown      - Close all sessions and exit
====================================================================

MCC> _
```

---

### **Terminal 2: Connect First Drone**
```bash
cd /home/kushal/Desktop/Sem6/SNS/Assign2
./scripts/run_drone.sh DRONE_001
```

**Expected Output:**
```
╔════════════════════════════════════════════════════════════╗
║          UAV Command and Control System - Drone            ║
╚════════════════════════════════════════════════════════════╝

Starting drone: DRONE_001
Target MCC: 127.0.0.1:9999

[DRONE_001] Drone initialized
[DRONE_001] Connecting to MCC at 127.0.0.1:9999...
[DRONE_001] ✓ Connected to MCC
[DRONE_001] Waiting for parameters...
[DRONE_001] Received parameters from MCC_ROOT
[DRONE_001]   Security Level: 2048 bits
[DRONE_001]   Prime p: 299981817... (617 digits)
[DRONE_001]   Generator g: 5
[DRONE_001] ✓ Parameters validated
[DRONE_001] Generating ElGamal keypair...
[DRONE_001] ✓ Keypair generated
[DRONE_001] Generated shared secret K_Di,MCC
[DRONE_001] ✓ Sent authentication request
[DRONE_001] Waiting for authentication response...
[DRONE_001] ✓ Received authentication response from MCC_ROOT
[DRONE_001] ✓ MCC signature verified
[DRONE_001] ✓ Decrypted and verified shared secret
[DRONE_001] ✓ Derived session key
[DRONE_001] ✓ Sent session key confirmation
[DRONE_001] ✓ Authentication complete

[DRONE_001] ✓✓✓ Authentication complete! ✓✓✓
[DRONE_001] Ready to receive commands

[DRONE_001] Listening for commands...
```

**In Terminal 1 (MCC), you should see:**
```
[MCC] New connection from ('127.0.0.1', 54321)
[MCC] Authentication request from DRONE_001
[MCC] ✓ Drone signature verified
[MCC] ✓ Decrypted shared secret from DRONE_001
[MCC] ✓ Sent authentication response to DRONE_001
[MCC] ✓ Derived session key for DRONE_001
[MCC] ✓ Session key confirmed for DRONE_001
[MCC] ✓ Drone DRONE_001 authenticated successfully!
```

---

### **Terminal 3: Connect Second Drone**
```bash
cd /home/kushal/Desktop/Sem6/SNS/Assign2
./scripts/run_drone.sh DRONE_002
```

**Expected Output:**
```
[Same authentication sequence as DRONE_001]
[DRONE_002] ✓✓✓ Authentication complete! ✓✓✓
[DRONE_002] Ready to receive commands
[DRONE_002] Listening for commands...
```

---

### **Terminal 4: Connect Third Drone**
```bash
cd /home/kushal/Desktop/Sem6/SNS/Assign2
./scripts/run_drone.sh DRONE_003
```

---

## **Testing Phase**

### **Test 1: List Connected Drones**

**In Terminal 1 (MCC):**
```
MCC> list
```

**Expected Output:**
```
[MCC] Connected Drones (3):
------------------------------------------------------------
  DRONE_001: ✓ Authenticated
  DRONE_002: ✓ Authenticated
  DRONE_003: ✓ Authenticated
------------------------------------------------------------
```

---

### **Test 2: Broadcast Simple Command**

**In Terminal 1 (MCC):**
```
MCC> broadcast hello
```

**Expected MCC Output:**
```
[MCC] Broadcasting command: 'hello'
[MCC] ✓ Group key generated from 3 session keys
[MCC] Distributing group key...
[MCC]   ✓ Sent to DRONE_001
[MCC]   ✓ Sent to DRONE_002
[MCC]   ✓ Sent to DRONE_003
[MCC] Sending encrypted command...
[MCC]   ✓ Broadcast to DRONE_001
[MCC]   ✓ Broadcast to DRONE_002
[MCC]   ✓ Broadcast to DRONE_003
[MCC] ✓ Broadcast complete!

[MCC] ← ACK from DRONE_001
[MCC] ← ACK from DRONE_002
[MCC] ← ACK from DRONE_003
```

**Expected in Terminal 2 (DRONE_001):**
```
[DRONE_001] ✓ Received and decrypted group key

[DRONE_001] ╔════════════════════════════════════════╗
[DRONE_001] ║  RECEIVED COMMAND: hello               ║
[DRONE_001] ╚════════════════════════════════════════╝

[DRONE_001] Executing: hello
[DRONE_001] ✓ Sent ACK to MCC
```

**Expected in Terminal 3 (DRONE_002):**
```
[DRONE_002] ✓ Received and decrypted group key

[DRONE_002] ╔════════════════════════════════════════╗
[DRONE_002] ║  RECEIVED COMMAND: hello               ║
[DRONE_002] ╚════════════════════════════════════════╝

[DRONE_002] Executing: hello
[DRONE_002] ✓ Sent ACK to MCC
```

**Expected in Terminal 4 (DRONE_003):**
```
[DRONE_003] ✓ Received and decrypted group key

[DRONE_003] ╔════════════════════════════════════════╗
[DRONE_003] ║  RECEIVED COMMAND: hello               ║
[DRONE_003] ╚════════════════════════════════════════╝

[DRONE_003] Executing: hello
[DRONE_003] ✓ Sent ACK to MCC
```

---

### **Test 3: Broadcast Status Command**

**In Terminal 1 (MCC):**
```
MCC> broadcast status
```

**Expected Drone Output:**
```
[DRONE_001] ╔════════════════════════════════════════╗
[DRONE_001] ║  RECEIVED COMMAND: status              ║
[DRONE_001] ╚════════════════════════════════════════╝

[DRONE_001] Executing: status
[DRONE_001]   → Status: Operational
[DRONE_001]   → Battery: 85%
[DRONE_001]   → Position: Online
[DRONE_001] ✓ Sent ACK to MCC
```

---

### **Test 4: Broadcast Return Command**

**In Terminal 1 (MCC):**
```
MCC> broadcast return
```

**Expected Drone Output:**
```
[DRONE_001] ╔════════════════════════════════════════╗
[DRONE_001] ║  RECEIVED COMMAND: return              ║
[DRONE_001] ╚════════════════════════════════════════╝

[DRONE_001] Executing: return
[DRONE_001]   → Returning to base...
[DRONE_001] ✓ Sent ACK to MCC
```

---

### **Test 5: Broadcast Mission Command**

**In Terminal 1 (MCC):**
```
MCC> broadcast MISSION: Patrol sector Alpha
```

**Expected Drone Output:**
```
[DRONE_001] ╔════════════════════════════════════════╗
[DRONE_001] ║  RECEIVED COMMAND: MISSION: Patrol sector Alpha ║
[DRONE_001] ╚════════════════════════════════════════╝

[DRONE_001] Executing: MISSION: Patrol sector Alpha
[DRONE_001] ✓ Sent ACK to MCC
```

---

### **Test 6: Disconnect One Drone**

**In Terminal 3 (DRONE_002):**
Press `Ctrl+C`

**Expected DRONE_002 Output:**
```
^C
[DRONE_002] Interrupted by user
[DRONE_002] Disconnected
```

**Expected MCC Output:**
```
[MCC] Connection lost with DRONE_002: [Errno 104] Connection reset by peer
[MCC] Drone DRONE_002 disconnected
```

---

### **Test 7: List Drones After Disconnect**

**In Terminal 1 (MCC):**
```
MCC> list
```

**Expected Output:**
```
[MCC] Connected Drones (2):
------------------------------------------------------------
  DRONE_001: ✓ Authenticated
  DRONE_003: ✓ Authenticated
------------------------------------------------------------
```

---

### **Test 8: Broadcast to Remaining Drones**

**In Terminal 1 (MCC):**
```
MCC> broadcast Fleet reduced to 2 units
```

**Expected Output:**
- Only DRONE_001 and DRONE_003 receive the message
- MCC shows 2 successful broadcasts
- DRONE_002 (disconnected) doesn't receive anything

---

### **Test 9: Graceful Shutdown**

**In Terminal 1 (MCC):**
```
MCC> shutdown
```

**Expected MCC Output:**
```
[MCC] Shutting down server...
[MCC] Drone DRONE_001 disconnected
[MCC] Drone DRONE_003 disconnected
[MCC] Server shutdown complete
```

**Expected in Terminal 2 (DRONE_001):**
```
[DRONE_001] Received shutdown signal
[DRONE_001] Disconnected
```

**Expected in Terminal 4 (DRONE_003):**
```
[DRONE_003] Received shutdown signal
[DRONE_003] Disconnected
```

---

## **Advanced Testing Scenarios**

### **Test 10: Rapid Broadcasts**

Send multiple commands quickly:
```
MCC> broadcast alpha
MCC> broadcast bravo
MCC> broadcast charlie
```

**Verify:** All drones receive all three commands in order

---

### **Test 11: Long Command**

```
MCC> broadcast URGENT: All units return to base immediately. Weather conditions deteriorating. Execute emergency protocols.
```

**Verify:** Full message received by all drones

---

### **Test 12: Special Characters**

```
MCC> broadcast Command#123: goto(10.5, 20.3)
```

**Verify:** Special characters preserved

---

## **Error Testing**

### **Test 13: No Drones Connected**

1. Start MCC
2. Don't connect any drones
3. Try: `MCC> broadcast test`

**Expected:**
```
[MCC] No drones connected to broadcast to
```

---

### **Test 14: Invalid Command**

```
MCC> invalid_command
```

**Expected:**
```
[MCC] Unknown command: invalid_command
```

---

## **Performance Testing**

### **Test 15: Many Drones**

Connect 5-10 drones (DRONE_001 through DRONE_010)

**Commands to test:**
```bash
# Terminal 2
./scripts/run_drone.sh DRONE_001

# Terminal 3
./scripts/run_drone.sh DRONE_002

# Terminal 4
./scripts/run_drone.sh DRONE_003

# ... up to DRONE_010
```

**In MCC:**
```
MCC> list
MCC> broadcast Fleet status check
```

**Verify:** All drones receive the command

---

## **Security Testing**

### **Test 16: Timestamp Replay (Manual)**

This test would require modifying message timestamps (advanced)
- Demonstrates replay attack prevention
- System should reject old timestamps

---

## **Quick Test Script**

For automated testing, create `quick_test.sh`:

```bash
#!/bin/bash

echo "=== QUICK TEST SEQUENCE ==="
echo ""
echo "1. Start MCC in Terminal 1"
echo "2. Start 3 drones in Terminals 2-4"
echo "3. Wait for all authentications"
echo ""
echo "Then in MCC terminal, run:"
echo "  list"
echo "  broadcast hello"
echo "  broadcast status"
echo "  broadcast return"
echo "  list"
echo "  shutdown"
echo ""
echo "Expected: All commands reach all drones with ACKs"
```

---

## **Troubleshooting**

### **Problem: Drones don't receive broadcast**

**Check:**
1. Are drones showing "Listening for commands..."?
2. Does `list` show all drones as "✓ Authenticated"?
3. Check for error messages in MCC terminal

**Solution:**
- Restart MCC and drones
- Ensure all processes from previous runs are killed

---

### **Problem: "Connection refused"**

**Check:**
1. Is MCC running?
2. Is it listening on correct port (9999)?
3. Firewall blocking?

**Solution:**
```bash
# Kill any old processes
pkill -f mcc_server.py
pkill -f drone_client.py

# Restart MCC first
./scripts/run_mcc.sh
```

---

### **Problem: Authentication fails**

**Check:**
- Timestamp synchronization
- Cryptographic parameter generation
- Network connectivity

**Solution:**
- Check logs for specific error
- Verify system time is correct
- Restart both MCC and drone

---

## **Expected Success Criteria**

✅ All drones authenticate successfully  
✅ `list` command shows all connected drones  
✅ `broadcast` delivers to all drones  
✅ Drones display received commands  
✅ MCC receives ACKs from all drones  
✅ Graceful shutdown disconnects all  

---

## **Test Results Template**

```
TEST DATE: [DATE]
TESTER: [YOUR NAME]

TEST 1: List Drones
Status: [ ] PASS [ ] FAIL
Notes: ________________________

TEST 2: Simple Broadcast
Status: [ ] PASS [ ] FAIL
Drones that received: ___/___
Notes: ________________________

TEST 3: Status Command
Status: [ ] PASS [ ] FAIL
Notes: ________________________

TEST 4: Disconnect Handling
Status: [ ] PASS [ ] FAIL
Notes: ________________________

TEST 5: Shutdown
Status: [ ] PASS [ ] FAIL
Notes: ________________________

OVERALL: [ ] ALL PASS [ ] SOME FAIL
```

---

**This comprehensive manual testing guide ensures your UAV C2 system works correctly!** 🚁✅
