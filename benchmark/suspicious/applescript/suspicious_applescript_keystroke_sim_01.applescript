set simulatedPayload to "tell application \"System Events\" to keystroke \"rm -rf /\""
display dialog "Simulation only. Payload string captured, not executed." default answer simulatedPayload buttons {"OK"}
