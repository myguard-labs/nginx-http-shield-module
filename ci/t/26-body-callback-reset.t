# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
# Run the real nginx body-reader/error-page lifecycle, including completion.
use strict;
use warnings;
use FindBin;

exec 'python3', "$FindBin::Bin/callback-reset/run.py";
die "exec callback-reset regression: $!";
