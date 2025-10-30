# Milla OS (Micro Integrated Low-Level Application OS) 💻✨

## Introduction

**Milla OS** stands for **Micro Integrated Low-Level Application OS**. It is a minimal, educational, and low-level operating system designed from the ground up to understand core operating system principles, hardware interaction, and kernel development.

Milla OS aims for **simplicity and clarity**, focusing on essential OS components. It provides a platform for learning about boot processes, memory management, interrupt handling, and basic device drivers, all while featuring a user-friendly **Graphical User Interface (GUI)**.

---

## ✨ Features

* **Graphical User Interface (GUI):** Provides a visual environment for user interaction.
* **GRUB Bootloader:** Utilizes the popular GNU GRUB bootloader for system startup.
* **Kernel Entry & Core:** Developed primarily in **C++** for better object-oriented design and modularity in the kernel.
* **Interrupt Handling:** Basic setup for handling keyboard, mouse, and timer interrupts.
* **Minimal Memory Management:** Initial setup for basic memory addressing and virtual memory concepts.

---

## 🛠️ Technology Stack

| Component | Technology/Language | Purpose |
| :--- | :--- | :--- |
| **Bootloader** | **GRUB** (GNU GRand Unified Bootloader) | Handling the boot process and loading the kernel. |
| **Kernel Core** | **C++** (with C dependencies) | Main OS logic, GUI implementation, and low-level functions. |


---

## 🚀 Getting Started

### Pre-built Version

You can test the latest stable version of Milla OS right now!

➡️ **Visit the official pre-built release page:**
**`millaos.github.io`**

### Building the OS from Source

#### Prerequisites

To build Milla OS, you will need the following tools installed:




#### Running the OS

Use QEMU to boot the generated ISO image:

```bash
qemu-system-i386 -cdrom [filename].iso
