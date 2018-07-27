#!/bin/bash
source /usr/local/rvm/scripts/rvm
git config --global user.name "NAME HERE"
git config --global user.email "email@example.com"
/usr/share/metasploit-framework/msfupdate --git-branch master
/bin/bash -c "cd /usr/local/bin/metasploitHelper && bash"
