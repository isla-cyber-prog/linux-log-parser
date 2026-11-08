# Linux Log Parser (Incident Response Monitor)

## Purpose
An automation project designed to mimic Blue Team Security Operations Centre (SOC) workflows. It parses authentication histories to discover real-time threat indications.

## How It Works
* Uses modular Python file operations to read internal system events line by line without causing memory issues.
* Tracks authentication failure occurrences utilizing dynamic dictionary counts.
* Evaluates active events against an alert baseline limit to trigger incident notifications automatically.

## Connection to Cyber Security Concepts
This script represents the practical implementation of *Defensive Security Principles: Monitoring, Detection, and Incident Response*. It highlights how analytical script logic can detect ongoing attacks (like automated brute-force attempts) before an exploit is successful.
