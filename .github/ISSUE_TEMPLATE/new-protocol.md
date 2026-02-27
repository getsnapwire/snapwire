---
name: New Protocol Detector
about: Propose a new AI protocol detector for the Sentinel proxy
title: "[Protocol] "
labels: protocol, enhancement
assignees: ''
---

## Protocol Name

<!-- e.g., Google Gemini Function Calling, AWS Bedrock Agent, etc. -->

## Detection Pattern

<!-- Describe the JSON structure that identifies tool calls in this protocol. -->

```json

```

## Example Payload

<!-- Provide a real or realistic request body that the detector should match. -->

```json

```

## Confidence Level

<!-- How reliably can this pattern be detected? (0.0 - 1.0) -->
<!-- 1.0 = unique marker (like jsonrpc method), 0.5 = heuristic match -->

- Suggested confidence: 

## References

<!-- Links to protocol documentation, specs, or examples. -->

- 

## Checklist

- [ ] I have checked that no existing detector already covers this protocol
- [ ] I can provide test cases for this detector
- [ ] The detection pattern does not conflict with existing protocol detectors
