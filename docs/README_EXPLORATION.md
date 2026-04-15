# Wirepeek Phase 2 Exploration — Complete Analysis

**Exploration Date:** April 14, 2026  
**Status:** ✅ Complete & Ready for Implementation  
**Effort Estimate:** 14-21 hours

---

## 📋 Documentation Index

This exploration includes 4 comprehensive documents:

### 1. **[EXPLORATION_SUMMARY.txt](./EXPLORATION_SUMMARY.txt)** ← START HERE
Executive summary of the entire exploration.
- Key findings (what exists vs. what's missing)
- Architectural insights
- Critical design decisions
- Integration points and next steps
- **Best for:** Quick overview before diving into details

### 2. **[PHASE2_EXPLORATION.md](./PHASE2_EXPLORATION.md)** ← DETAILED ANALYSIS
In-depth exploration of the wirepeek project.
- Current architecture walkthrough (all 6 major components)
- Data structures for stream tracking (ConnectionKey)
- Packet data structures (PacketView, OwnedPacket)
- Dissection pipeline (Layer 2→3→4)
- Current CLI usage
- Build structure and dependencies
- Phase 2 design points with pseudocode API
- **Best for:** Understanding current codebase and design rationale

### 3. **[ARCHITECTURE_OVERVIEW.txt](./ARCHITECTURE_OVERVIEW.txt)** ← VISUAL REFERENCE
Diagrams and visual architecture.
- Phase 1 pipeline (capture + dissection)
- Phase 2 reassembler (with internal state diagram)
- Phase 3 future (HTTP parser)
- Data structure relationships
- Threading model
- File structure tree
- Key design decisions and trade-offs
- **Best for:** Understanding the big picture visually

### 4. **[PHASE2_IMPLEMENTATION_ROADMAP.md](./PHASE2_IMPLEMENTATION_ROADMAP.md)** ← IMPLEMENTATION GUIDE
Detailed implementation roadmap with code sketches.
- Complete API definition (ready to code)
- Implementation layer breakdown (4 layers)
- Internal state management design
- Segment insertion algorithm (pseudocode)
- CLI integration code (example)
- Build system changes
- Implementation checklist (35 tasks)
- Testing strategy
- Success criteria
- **Best for:** Starting actual implementation

---

## 🎯 Quick Facts

| Aspect | Finding |
|--------|---------|
| **Project Size** | ~2000 LOC production + tests |
| **Phase Status** | Phase 1 complete, Phase 2 ready |
| **Files Analyzed** | 13 headers + 8 implementations + 2 CMakeLists |
| **New Files Needed** | 2 (header + implementation) |
| **Modified Files** | 2 (CMakeLists + main.cpp) |
| **Key Dependencies** | fmt, spdlog, pcap, cli11, xxhash |
| **Estimated Effort** | 14-21 hours |
| **Complexity** | Medium (segment reordering, buffering) |

---

## ✅ What Already Exists

1. **ConnectionKey** — Perfect 5-tuple structure with custom hash
2. **Packet Data Structures** — PacketView (zero-copy) + OwnedPacket (buffering)
3. **Dissection Pipeline** — Ethernet → IP → TCP/UDP (all headers parsed)
4. **Error Handling** — DissectResult<T> with graceful degradation
5. **Build System** — CMake with FetchContent, xxhash already linked
6. **CLI Structure** — Callback-based packet processing (hot-path compatible)

---

## ❌ What's Missing

1. **TcpReassembler Class** — No segment reordering
2. **Stream State Management** — No per-stream buffering
3. **Segment Assembly Algorithm** — No in-order reassembly
4. **Output Emission** — No callback mechanism for streams
5. **CLI Integration** — Reassembler not used yet

---

## 🏗️ Implementation Layers

```
Layer 4: CLI Integration (main.cpp)
   └─ Use reassembler callback in capture loop

Layer 3: Reassembler Public API (header)
   └─ TcpReassembler class with ProcessPacket() + Flush()

Layer 2: Internal State (implementation)
   └─ PerStreamState struct + segment insertion logic

Layer 1: Build System (CMakeLists.txt)
   └─ Add reassembler source file
```

---

## 🔄 Data Flow

```
PacketView (capture buffer)
    ↓ (Dissect)
DissectedPacket (extracted headers)
    ↓ (ProcessPacket)
TcpReassembler (buffering + reordering)
    ↓ (callback)
ReassembledStream (in-order bytes)
    ↓ (Phase 3)
HTTP Parser (extract requests/responses)
```

---

## 🎓 Key Insights

1. **One ConnectionKey = Two Directions**
   - Need StreamDirection enum to distinguish Client→Server from Server→Client
   - Same connection tracked together but output separately

2. **Sequence Number Wraparound**
   - TCP seq numbers wrap at 2^32
   - Use signed comparison: `(int32_t)(a - b) < 0`

3. **Memory Safety**
   - PacketView is short-lived (capture buffer)
   - Reassembler must copy to OwnedPacket for long-term storage
   - Buffer limits (10MB/stream, 100MB total) prevent DoS

4. **Output Frequency**
   - Emit on PSH (message boundary)
   - Emit on FIN (stream closing)
   - Emit on gap-filling (contiguous data available)
   - Let Phase 3 decide further batching

---

## 🚀 Next Steps

### Phase 2a: Foundation (4-6 hours)
- [ ] Create tcp_reassembler.h header
- [ ] Implement basic buffering + assembly
- [ ] Handle SYN/FIN/RST
- [ ] Write unit tests

### Phase 2b: Integration (2-3 hours)
- [ ] Integrate into CLI capture loop
- [ ] Add stream callback output
- [ ] Test with real pcaps
- [ ] Add statistics

### Phase 2c: Advanced (4-6 hours)
- [ ] Out-of-order buffering
- [ ] Sequence wraparound handling
- [ ] Timeout-based cleanup
- [ ] Buffer limits

### Phase 2d: Testing (4-6 hours)
- [ ] Unit test coverage
- [ ] Integration tests
- [ ] Performance benchmarks
- [ ] Edge case handling

---

## 📊 Code Statistics

| Component | LOC | Status |
|-----------|-----|--------|
| Dissectors (Eth, IP, TCP, UDP) | 300 | ✅ Complete |
| Capture (pcap, file) | 200 | ✅ Complete |
| CLI (main) | 120 | ⏳ Ready for modification |
| **Reassembler (NEW)** | **650-800** | 🚀 Ready to implement |

---

## 🔍 Questions Answered

**Q: What data structures exist for stream tracking?**  
A: `ConnectionKey` (5-tuple) with custom FNV-1a hash. Perfect for stream identification.

**Q: How does the dissection pipeline work?**  
A: Sequential layers (Eth → IP → TCP/UDP), graceful degradation, all zero-copy via `span<>`.

**Q: Where does TCP reassembly plug in?**  
A: Between dissection and CLI output. Receives `DissectedPacket`, outputs `ReassembledStream` via callback.

**Q: What feeds into Phase 3?**  
A: In-order, contiguous TCP payload bytes with stream metadata (ConnectionKey, direction, timestamps).

---

## 📚 Recommended Reading Order

1. Start with **EXPLORATION_SUMMARY.txt** (10 min)
2. Skim **ARCHITECTURE_OVERVIEW.txt** diagrams (10 min)
3. Read **PHASE2_EXPLORATION.md** (30 min)
4. Study **PHASE2_IMPLEMENTATION_ROADMAP.md** (30 min)
5. Start implementation with roadmap as guide

Total reading time: ~1.5 hours before coding

---

## 🎯 Success Criteria

- ✅ Reassembler passes unit tests
- ✅ Handles real-world packet captures correctly
- ✅ Memory stays within configured limits
- ✅ No crashes on malformed input
- ✅ Seamless CLI integration
- ✅ Output ready for HTTP parser (Phase 3)

---

## 📞 Questions?

Refer to the relevant document:
- **"How do I start coding?"** → PHASE2_IMPLEMENTATION_ROADMAP.md
- **"What's the overall design?"** → ARCHITECTURE_OVERVIEW.txt
- **"What are the current limitations?"** → PHASE2_EXPLORATION.md
- **"What are the next steps?"** → EXPLORATION_SUMMARY.txt

---

**Created:** April 14, 2026  
**Status:** Analysis Complete ✅ Ready for Implementation 🚀
