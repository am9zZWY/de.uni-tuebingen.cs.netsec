#!/bin/bash

pandoc -V CJKmainfont="KaiTi" -V geometry:a4paper -V geometry:margin=2cm README.md -o NetSec.pdf