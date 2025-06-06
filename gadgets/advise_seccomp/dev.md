# Developer Notes

This file complements the README file with implementation details specific to this gadget. It includes diagrams that illustrate how eBPF programs interact with eBPF maps. These visualizations help clarify the internal data flow and logic, making it easier to understand, maintain, and extend the gadget.

## Program-Map interactions

The following diagrams are generated using the `ig image inspect` command. Note they are a best-effort representation of the actual interactions, as they do not account for conditionals in the code that may prevent certain program–map interactions from occurring at runtime.

### Flowchart

```mermaid
flowchart LR
gadget_mntns_filter_map[("gadget_mntns_filter_map")]
syscalls_per_mntns[("syscalls_per_mntns")]
ig_seccomp_e -- "Lookup+Update" --> syscalls_per_mntns
ig_seccomp_e["ig_seccomp_e"]
```

### Sequence Diagram

```mermaid
sequenceDiagram
box eBPF Programs
participant ig_seccomp_e
end
box eBPF Maps
participant syscalls_per_mntns
end
ig_seccomp_e->>syscalls_per_mntns: Lookup
ig_seccomp_e->>syscalls_per_mntns: Update
```
