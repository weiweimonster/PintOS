# -*- perl -*-
use strict;
use warnings;
use tests::tests;
use tests::random;
check_expected (IGNORE_EXIT_CODES => 1, [<<'EOF']);
(cache-coalesce) begin
(cache-coalesce) create "testfile"
(cache-coalesce) open "testfile"
(cache-coalesce) writing "testfile"
(cache-coalesce) close "testfile"
(cache-coalesce) open "testfile"
(cache-coalesce) reading "testfile"
(cache-coalesce) close "testfile"
(cache-coalesce) end
EOF
pass;
