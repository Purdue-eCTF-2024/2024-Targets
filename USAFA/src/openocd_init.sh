#!/bin/bash

openocd -f interface/cmsis-dap.cfg -f target/max78000.cfg -c "init"
