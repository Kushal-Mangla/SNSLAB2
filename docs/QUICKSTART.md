# Quick Start Guide - UAV C2 System# QUICK START GUIDE



## 🚀 Get Started in 3 Steps## 🚀 Fast Setup (3 Steps)



### Step 1: Setup (One-time)### Step 1: Install Dependencies

```bash

cd /home/kushal/Desktop/Sem6/SNS/Assign2```bash

./scripts/setup.shcd /home/kushal/Desktop/Sem6/SNS/Assign2

```pip install -r requirements.txt

This creates a virtual environment and installs dependencies.```



---### Step 2: Test the System



### Step 2: Start MCC Server```bash

```bash./test_system.sh

# Terminal 1```

./scripts/run_mcc.sh

```### Step 3: Run the System



You'll see:**Terminal 1 - Start MCC:**

``````bash

╔════════════════════════════════════════════════════════════╗./mcc_server.py

║              Mission Control Center (MCC)                  ║```

╚════════════════════════════════════════════════════════════╝

**Terminal 2 - Start Drone 1:**

[MCC] Generating 2048-bit ElGamal parameters...```bash

[MCC] Parameters generated in X.XX seconds./drone_client.py DRONE_001

[MCC] Server started on 0.0.0.0:5000```

[MCC] Waiting for drone connections...

**Terminal 3 - Start Drone 2:**

MCC> _```bash

```./drone_client.py DRONE_002

```

---

---

### Step 3: Connect Drones

```bash## 🎮 Using the System

# Terminal 2

./scripts/run_drone.sh DRONE_001In the MCC terminal (Terminal 1):



# Terminal 3```bash

./scripts/run_drone.sh DRONE_002# List connected drones

MCC> list

# Terminal 4

./scripts/run_drone.sh DRONE_003# Send command to all drones

```MCC> broadcast status



Each drone will authenticate and connect.# More commands

MCC> broadcast return

---MCC> broadcast goto 34.5,-120.2



## 🎮 Use the System# Shutdown

MCC> shutdown

### In MCC Terminal:```



#### List Connected Drones---

```

MCC> list## ⚡ Key Features Implemented

```

Output:✅ Manual ElGamal encryption/decryption  

```✅ Manual ElGamal digital signatures  

Connected Drones: 3✅ 2048-bit prime generation (Miller-Rabin)  

  1. DRONE_001 [Ready] - Session: sk_xxxxx✅ Modular arithmetic from scratch  

  2. DRONE_002 [Ready] - Session: sk_yyyyy✅ Mutual authentication protocol  

  3. DRONE_003 [Ready] - Session: sk_zzzzz✅ Session key derivation (SHA-256)  

```✅ Group key aggregation  

✅ AES-256-CBC encryption  

#### Broadcast Command to All Drones✅ HMAC-SHA256 integrity  

```✅ Multi-threaded server  

MCC> broadcast "MISSION: Return to base"✅ Concurrent drone support  

```

All drones receive and execute the command.---



#### Shutdown System## 📊 Expected Timeline

```

MCC> shutdown- **Prime generation**: 15-60 seconds (one-time at MCC startup)

```- **Drone authentication**: 1-3 seconds per drone

Gracefully disconnects all drones and stops the server.- **Command broadcast**: <1 second



------



## 🧪 Run Tests## 🔍 Quick Test Commands



```bash```bash

./scripts/run_all_tests.sh# Test crypto primitives

```python3 crypto_utils.py



Expected output:# Test utilities

```python3 utils.py

╔════════════════════════════════════════════════════════════╗

║                    TEST SUMMARY                            ║# Check file structure

╠════════════════════════════════════════════════════════════╣ls -lh

║  Unit Tests:        ✓ PASSED (14/14)                      ║

║  Integration Tests: ✓ PASSED (5/5)                        ║# Check dependencies

╠════════════════════════════════════════════════════════════╣pip list | grep pycryptodome

║  Overall Status:    ✓ ALL TESTS PASSED                    ║```

╚════════════════════════════════════════════════════════════╝

```---



---## ⚠️ Important Notes



## 📁 Project Structure1. **First MCC startup takes time** - Prime generation for 2048-bit security

2. **Keep MCC running** - Use screen/tmux for persistent sessions

```3. **Each drone needs unique ID** - DRONE_001, DRONE_002, etc.

Assign2/4. **Broadcast requires authenticated drones** - Connect drones first

├── src/          # Source code (crypto, server, client, protocol)

├── tests/        # Test suites (unit & integration)---

├── scripts/      # Executable scripts (setup, run)

├── docs/         # Documentation## 🐛 Quick Fixes

└── README.md     # Full documentation

```**Problem: Import error**

```bash

---pip install pycryptodome

```

## 📖 Documentation

**Problem: Prime generation slow**

- **README.md**: Complete system documentation- Wait 30-60 seconds on first run

- **docs/PROTOCOL.md**: Protocol specification- This happens once per MCC startup

- **docs/TEST_DOCUMENTATION.md**: Test details- For testing: Change SL to 1024 in config.py

- **docs/TEST_RESULTS.md**: Test results

**Problem: Connection refused**

---- Ensure MCC is running first

- Check: ps aux | grep mcc_server

## ⚙️ Configuration

---

Edit `src/config.py` to customize:

- Security level (default: 2048 bits)## 📞 Testing Checklist

- Server port (default: 5000)

- Timestamp window (default: 60 seconds)- [ ] Install pycryptodome

- [ ] Run ./test_system.sh

---- [ ] Start MCC server

- [ ] Connect 2-3 drones

## 🔧 Troubleshooting- [ ] Run 'list' command

- [ ] Run 'broadcast status' command

### Issue: "Virtual environment not found"- [ ] Verify drones receive command

**Solution**: Run `./scripts/setup.sh`- [ ] Run 'shutdown' command



### Issue: "Port already in use"---

**Solution**: Change port in `src/config.py` or kill existing process

**For full documentation, see README.md**

### Issue: "Module not found"
**Solution**: 
```bash
source .venv/bin/activate
export PYTHONPATH="$(pwd)/src:$PYTHONPATH"
```

---

## ✅ What Works

✅ Manual ElGamal cryptography (2048-bit)  
✅ Mutual authentication with digital signatures  
✅ Session key derivation (unique per session)  
✅ Group key broadcast encryption  
✅ Multi-threaded MCC server  
✅ CLI interface (list, broadcast, shutdown)  
✅ Replay attack prevention  
✅ 100% test pass rate (19/19 tests)  

---

## 🎯 Assignment Compliance

This implementation meets all requirements for **SNS Assignment 2**:
- ✅ Manual ElGamal (no high-level crypto)
- ✅ 2048-bit minimum security
- ✅ All 4 protocol phases
- ✅ Multi-threaded architecture
- ✅ Comprehensive testing

---

**Ready to use!** 🚀
