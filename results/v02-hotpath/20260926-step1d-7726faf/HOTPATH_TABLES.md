## realpath/lstat mechanism (phase X; rotated rounds, shell-timed)

| comparison | ms per run |
|---|---|
| kernel − base | +2.74 (90% CI +1.99..+3.55) |
| nostore − kernel | +4.30 (90% CI +3.57..+5.32) |
| canon_only − kernel | +0.65 (90% CI -0.62..+1.54) |
| nostore_nocanon − kernel | +1.44 (90% CI +0.33..+2.54) |
| nostore − nostore_nocanon | +2.53 (90% CI +1.91..+4.07) |
