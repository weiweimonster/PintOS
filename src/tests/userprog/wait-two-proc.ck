# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(wait-two-proc) begin
(child-simple) run
child-simple: exit(81)
(child-simple) run
child-simple: exit(81)
(wait-two-proc) wait(exec()) = 81
(wait-two-proc) wait(exec()) = 81
(wait-two-proc) end
wait-two-proc: exit(0)
EOF
pass;
