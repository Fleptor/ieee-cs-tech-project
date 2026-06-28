# **Cipher eBPF Kernel Architecture**

This document serves as the technical blueprint for the kernel-ebpf directory in the Cipher project. It explains the underlying technologies, networking fundamentals, Linux kernel mechanisms, compiler directives, and the Deep Packet Inspection (DPI) logic utilized by our system.

## **1\. Repository Structure & The Memory Contract**

The kernel-ebpf folder contains two critical files that define our filtering engine:

1. **kernel\_space.c**: The core logic program compiled into eBPF bytecode.  
2. **shared\_defs.h**: The Application Binary Interface (ABI) contract between the kernel and the user-space.

### **The shared\_defs.h Contract**

Because the eBPF program and Zakaria's Rust backend operate in completely different memory spaces (Kernel Space vs. User Space), they cannot directly share variables. They communicate by passing raw bytes through shared memory.  
shared\_defs.h holds the exact definition of struct log\_event and the bitwise triage flags (e.g., F\_ANOMALY). By isolating this into a header file, the Rust backend can use tools like bindgen (or manual \#\[repr(C, packed)\] mapping) to generate a mirror-image struct. This guarantees that when the kernel writes a 16-byte IPv6 address into the buffer, the Rust backend reads exactly 16 bytes, preventing memory alignment corruption.

## **2\. Networking Technologies Explained**

To understand how our engine processes traffic, it is essential to understand the encapsulation of network packets. When a packet arrives at our physical Network Interface Card (NIC), it is layered like an onion:

* **Layer 2 (Data Link \- Ethernet):** The outermost layer. It contains the Source and Destination **MAC Addresses** (physical hardware IDs). We extract this to perform strict hardware-level bans via our MAC\_list.  
* **Layer 3 (Network \- IP):** The next layer inside. It contains the Source and Destination **IP Addresses** (IPv4 or IPv6) and tells us what type of protocol is hiding in the next layer. We use this to block known malicious actors via our Blocked\_IPV4s and Blocked\_IPV6s lists.  
* **Layer 4 (Transport \- TCP/UDP/ICMP):** The core payload carrier.  
  * **TCP:** A connection-oriented protocol. It uses "Flags" (SYN, ACK, FIN) to maintain state. We inspect these flags to detect impossible states (like an attacker sending SYN and FIN simultaneously).  
  * **UDP:** A connectionless protocol. It has no stateful flags, so we must inspect the actual application payload (e.g., reading DNS headers) to find anomalies.  
  * **ICMP:** Used for network diagnostics (Ping). We monitor payload sizes to prevent data smuggling (Ping of Death).

*Note on Endianness:* Network traffic travels over the wire in **Big-Endian** format. Our local CPUs operate in **Little-Endian**. Therefore, we must use kernel functions like bpf\_ntohs() (Network-to-Host Short) to flip the bytes before we can read port numbers or packet lengths.

## **3\. Core eBPF & XDP Concepts**

### **What is eBPF?**

eBPF (Extended Berkeley Packet Filter) allows us to run sandboxed, verified C programs directly within the Linux kernel without changing kernel source code or writing risky kernel modules.

### **XDP (eXpress Data Path)**

Our program attaches to the **XDP** hook. XDP is the lowest possible layer in the Linux networking stack. It operates directly inside the NIC driver's page pool, *before* the Linux kernel even allocates memory (an sk\_buff) to process the packet. By acting here, we can drop (XDP\_DROP) malicious packets with near-zero CPU overhead.

### **eBPF Maps**

eBPF programs trigger millions of times a second and cannot use global variables or dynamically allocate memory (malloc). To store state, we use **eBPF Maps**:

* **Array Maps (BPF\_MAP\_TYPE\_ARRAY):** For static index lookups (e.g., Interface\_Map holding WAN/LAN OS indices).  
* **LRU Hash Maps (BPF\_MAP\_TYPE\_LRU\_HASH):** For active quarantine lists. LRU (Least Recently Used) guarantees ![][image1] lookup speed and ensures that if an attacker floods our network, the kernel automatically evicts the oldest entries to prevent memory exhaustion crashes.  
* **Ring Buffers (BPF\_MAP\_TYPE\_RINGBUF):** A high-speed, lockless queue streaming telemetry (struct log\_event) to the Rust backend.

## **4\. Compiler Directives & Kernel Syntax**

### **The SEC() Macro (ELF Sections)**

At the top of our C file, we define \#define SEC(NAME) \_\_attribute\_\_((section(NAME), used)).  
When Clang compiles our C code into an object file (.o), it creates an **ELF (Executable and Linkable Format)** binary. An ELF file is divided into different "sections" (like drawers in a filing cabinet).  
The SEC("xdp") and SEC(".maps") macros force the compiler to put our code and variables into specifically named drawers. When the user-space loader (Aya in Rust) reads the .o file, it doesn't just blindly execute code. It looks in the .maps drawer to know exactly how much memory to allocate in the kernel for our hash tables, and it looks in the xdp drawer to extract the bytecode it needs to attach to the network driver.

### **\_\_always\_inline**

Forces the compiler to copy a function's code directly into the caller. The eBPF virtual machine restricts nested function calls and strictly limits the memory stack to 512 bytes. By inlining helpers like log\_v4, we avoid stack overflows and verifier rejections.

### **Explicit Integer Types**

We use \_\_u8, \_\_u16, \_\_u32, and \_\_be16. These guarantee exact bit-widths across different CPU architectures, which is mandatory when slicing precise network packets.

## **5\. The Packet Inspection Pipeline (kernel\_space.c)**

The xdp\_router\_prog function executes for every single packet hitting the transparent bridge.

### **Step 1: Memory Bounds Checking (The Verifier)**

The Linux kernel includes a strict "Verifier" that statically analyzes our bytecode before it runs. If there is *any* mathematical possibility our code reads outside the bounds of the packet, the Verifier rejects the program.

* We use void \*data (start) and void \*data\_end (end).  
* Before casting memory to a TCP header, we compute dynamic lengths (e.g., tcp\_hdr\_len \= tcph-\>doff \* 4;) and prove to the verifier it is safe: if ((void \*)tcph \+ tcp\_hdr\_len \> data\_end) return XDP\_PASS;

### **Step 2: The Fast-Path Quarantine Check**

We extract the source MAC and IP. We check if they exist in MAC\_list or Blocked\_IPV4s.

* **If found:** We instantly return XDP\_DROP. The packet is destroyed at the hardware level.  
* **If not found:** The packet proceeds to Layer 4 DPI.

### **Step 3: Layer 4 Deep Packet Inspection (DPI)**

* **TCP (Handle\_TCP):** We inspect flags for state violations (e.g., concurrent SYN/FIN). We evaluate the destination port, explicitly tagging legacy plaintext protocols (Telnet, FTP) with F\_LEGACY\_DROP.  
* **UDP (Handle\_UDP):** We perform micro-DPI. For instance, on port 5355 (LLMNR), we cast the payload to a DNS header and verify the query count to block malformed exploits. For DHCP, we track directionality via Interface\_Map to detect Rogue DHCP servers (F\_INFRA\_ALERT).

### **Step 4: Telemetry Dispatch**

If a packet requires logging, we allocate a block inside the events Ring Buffer, populate it with the log\_event struct and our Bitwise Triage Flags, and submit it asynchronously to Zakaria's backend for behavioral analysis.

[image1]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACsAAAAaCAYAAAAue6XIAAABhklEQVR4Xu2WDU0EMRBGqwELaMACFrCABSzgAAlIwAEOcIABBMA+dr9LmXR+SvYukOxLmr302s7X6cy0rR0cnIWbpV3ZzoDZ8SG3W6sseL+0F9uZwJy3VlvfBaMfS3vd2mdbRUe8t9io999jW21Mc93Wiey4B0MItv2Ced5mmMs8Nu/BRhFdgthhMZrngae2Cn42/Qilf4Q2gBBvjMA2NlKIm8hzwH+MwQs9D1t/REUsToi8f2IkwnLX1nHWKGHDZiMqYuWMEMUjHoqQQbvgKDQsFbGETDbmO/MzrwJHxGJ9eZKBLDkqYiEdo/KUIa/2cS2xXiUQu4rNjhFYyJ7AnxSr8mRFSWxURWA3sRLCdwQb8RZRcu4Rs1G9/gGD8HB/IfCbZMrE6Fr26NfxLhwoVQOgbGFU154KNEY8jwu9I0ZgfNRsOEHF+yfYNYWfSXwzkaJUzAtwscy+2n6FrRKzeAl8NkqPkAF6RPG9GBwj4TMDoce8rPTtDoZJzCjjLeTHxYUe/Fu+AKTKfv5X1aAhAAAAAElFTkSuQmCC>