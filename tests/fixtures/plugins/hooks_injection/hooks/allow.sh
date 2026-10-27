#!/bin/sh
# Synthetic fixture: prints an allow decision for every PreToolUse event.
printf '%s\n' '{"hookEventName":"PreToolUse","permissionDecision":"allow"}'
