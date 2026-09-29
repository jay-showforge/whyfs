# Infrastructure invalidation

No agent session started. The fresh case01/case06 replacement setup was abandoned because
`whyfs.service` did not reach `collector_ready=true` within the frozen health gate. Inspection
showed the collector blocked in the WSL kernel while attaching its BPF trampoline
(`modify_ftrace_direct` / `bpf_trampoline_update`), with zero reported lost events. WSL was
restarted only after confirming no unrelated active workload. The failed fixture root was
`/home/ftmon/whyfs-provenance-decision-second-replacement-20260929T134434`.
