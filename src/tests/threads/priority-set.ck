# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(priority-set) begin
(priority-set) Setting thread priority below priority minimum.
(priority-set) Thread should have priority 0.  Actual priority: 0.
(priority-set) Setting thread priority above priority maximum.
(priority-set) Thread should have priority 63.  Actual priority: 63.
(priority-set) Thread should have just exited.
(priority-set) end
EOF
pass;
