# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(cache-hit-rate) begin
(cache-hit-rate) Hit rate 1 must be less than hit rate 2
(cache-hit-rate) end
cache-hit-rate: exit(0)
EOF
pass;
