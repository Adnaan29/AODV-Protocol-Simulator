# 📡 AODV Protocol Simulator (with PCAP Export)

This project is an interactive **AODV (Ad-hoc On-demand Distance Vector) routing protocol simulator** built using Python and Pygame.  
It visually demonstrates route discovery, route maintenance, packet flow, node mobility, and failure handling in mobile ad-hoc networks (MANETs).

The simulator also supports **PCAP-style packet logging**, allowing generated routing events to be analyzed externally.

---

## 🧠 Project Overview

AODV is a reactive routing protocol designed for dynamic wireless networks where nodes are free to move. Routes are discovered **only when required**, reducing unnecessary overhead.

This simulator allows users to:
- Visualize how AODV discovers routes
- Observe packet propagation (RREQ, RREP, DATA, RERR)
- Simulate node mobility and link failures
- Track routing events in real time
- Export routing activity in PCAP-like format

---

## ⚙️ Key Features

- Interactive graphical simulation
- Real-time packet animation
- On-demand route discovery (RREQ / RREP)
- Route maintenance and error handling (RERR)
- Node mobility simulation
- Adjustable simulation speed
- Event logging panel
- PCAP-style export for packet analysis
- Source and destination node selection via mouse

---

## 📡 AODV Packet Types Simulated

| Packet | Description |
|------|------------|
| RREQ | Route Request (broadcast) |
| RREP | Route Reply (unicast) |
| DATA | Data transmission packet |
| RERR | Route Error (link break) |

Each packet type is color-coded and animated across the network.

---

## 🔁 How the Simulation Works

### 1. Route Discovery
- Source node broadcasts RREQ packets
- Intermediate nodes forward RREQs
- Destination responds with RREP
- Multiple paths may be discovered

### 2. Route Establishment
- Best route is selected based on hop count
- RREP travels back to the source
- Data transmission begins

### 3. Route Maintenance
- Nodes may move dynamically
- Link breaks trigger RERR packets
- New route discovery is initiated if required

---

## 🖥️ User Interface Controls

- **Set Nodes** – Change number of nodes in the network
- **RUN SIM** – Start AODV route discovery
- **RESET** – Clear simulation state
- **SIM RERR** – Simulate route failure
- **NEW FORM** – Regenerate network topology
- **Mobility Toggle** – Enable/disable node movement
- **Speed Slider** – Control animation speed
- **GENERATE PCAP** – Export captured packets

---

## 📄 PCAP Export

The simulator records routing activity during execution and can generate a **PCAP-style text file** containing:

- Timestamp
- Packet type
- Source node
- Destination node
- Hop count
- Routing path

These files can be opened in Wireshark (as text reference) or used for educational analysis.

---

## 🛠️ Technology Stack

- Python 3
- Pygame
- Standard Python libraries:
  - math
  - random
  - time
  - collections
  - enum
  - datetime

---

## 🚀 How to Run

### Install Dependencies
```bash
pip install pygame
```
## 👥 Contributors

- **Adnaan Momin** – [GitHub](https://github.com/Adnaan29)
- **Tejas Abhang** – [GitHub](https://github.com/TejasAbhang77)
